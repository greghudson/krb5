/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krad/remote.c - Protocol code for libkrad */
/*
 * Copyright 2013 Red Hat, Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <k5-int.h>
#include <k5-queue.h>
#include "internal.h"

#include <string.h>
#include <unistd.h>

#include <sys/un.h>

#define FLAGS_READ (VERTO_EV_FLAG_PERSIST | VERTO_EV_FLAG_IO_CLOSE_FD | \
                    VERTO_EV_FLAG_IO_ERROR | VERTO_EV_FLAG_IO_READ)
#define FLAGS_WRITE (FLAGS_READ | VERTO_EV_FLAG_IO_WRITE)

TAILQ_HEAD(request_head, request_st);

typedef struct request_st request;
struct request_st {
    TAILQ_ENTRY(request_st) list;
    krad_remote *rr;
    krad_packet *request;
    krad_cb cb;
    void *data;
    verto_ev *timer;
    time_t timeout;
    size_t retries;
    size_t sent;
};

struct krad_remote_st {
    krb5_context kctx;
    verto_ctx *vctx;
    verto_ev *io;
    char *secret;
    struct addrinfo *info;
    struct request_head list;
    char buffer_[KRAD_PACKET_SIZE_MAX];
    krb5_data buffer;
};

static void
on_io(verto_ctx *ctx, verto_ev *ev);

/* Iterate over the set of outstanding packets. */
static const krad_packet *
iterator(request **out)
{
    request *tmp = *out;

    if (tmp == NULL)
        return NULL;

    *out = TAILQ_NEXT(tmp, list);
    return tmp->request;
}

/* Create a new request. */
static krb5_error_code
request_new(krad_remote *rr, krad_packet *rqst, time_t timeout, size_t retries,
            krad_cb cb, void *data, request **out)
{
    request *tmp;

    tmp = calloc(1, sizeof(request));
    if (tmp == NULL)
        return ENOMEM;

    tmp->rr = rr;
    tmp->request = rqst;
    tmp->cb = cb;
    tmp->data = data;
    tmp->timeout = timeout;
    tmp->retries = retries;

    *out = tmp;
    return 0;
}

/* Finish a request, calling the callback and freeing it. */
static inline void
request_finish(request *req, krb5_error_code retval,
               const krad_packet *response)
{
    if (retval != ETIMEDOUT)
        TAILQ_REMOVE(&req->rr->list, req, list);

    req->cb(retval, req->request, response, req->data);

    if (retval != ETIMEDOUT) {
        krad_packet_free(req->request);
        verto_del(req->timer);
        free(req);
    }
}

/* Handle when packets receive no response within their alloted time. */
static void
on_timeout(verto_ctx *ctx, verto_ev *ev)
{
    request *req = verto_get_private(ev);

    req->timer = NULL;          /* Void the timer event. */

    /* If we have more retries to perform, resend the packet. */
    if (req->retries-- > 1) {
        req->sent = 0;
        verto_set_flags(req->rr->io, FLAGS_WRITE);
        return;
    }

    request_finish(req, ETIMEDOUT, NULL);
}

/* Connect to the remote host. */
static krb5_error_code
remote_connect(krad_remote *rr)
{
    int i, sock = -1;
    verto_ev *ev;

    sock = socket(rr->info->ai_family, rr->info->ai_socktype,
                  rr->info->ai_protocol);
    if (sock < 0)
        return errno;

    i = connect(sock, rr->info->ai_addr, rr->info->ai_addrlen);
    if (i < 0) {
        i = errno;
        close(sock);
        return i;
    }

    ev = verto_add_io(rr->vctx, FLAGS_READ, on_io, sock);
    if (ev == NULL) {
        close(sock);
        return ENOMEM;
    }

    rr->io = ev;
    verto_set_private(rr->io, rr, NULL);
    return 0;
}

/* Disconnect and reconnect to the remote host. */
static krb5_error_code
remote_reconnect(krad_remote *rr, int errnum)
{
    krb5_error_code retval;
    const krb5_data *tmp;
    request *r;

    verto_del(rr->io);
    rr->io = NULL;
    retval = remote_connect(rr);
    if (retval != 0)
        return retval;

    TAILQ_FOREACH(r, &rr->list, list) {
        tmp = krad_packet_encode(r->request);

        if (r->sent == tmp->length) {
            /* Error out sent requests. */
            request_finish(r, errnum, NULL);
        } else {
            /* Reset partially sent requests. */
            r->sent = 0;
        }
    }

    return 0;
}

/* Close the connection and call the callbacks of all oustanding requests. */
static void
remote_shutdown(krad_remote *rr, int errnum)
{
    verto_del(rr->io);
    rr->io = NULL;
    while (!TAILQ_EMPTY(&rr->list))
        request_finish(TAILQ_FIRST(&rr->list), errnum, NULL);
}

/* Write data to the socket. */
static void
on_io_write(krad_remote *rr)
{
    const krb5_data *tmp;
    request *r;
    int i;

    TAILQ_FOREACH(r, &rr->list, list) {
        tmp = krad_packet_encode(r->request);

        /* If the packet has already been sent, do nothing. */
        if (r->sent == tmp->length)
            continue;

        /* Send the packet. */
        i = sendto(verto_get_fd(rr->io), tmp->data + r->sent,
                   tmp->length - r->sent, 0, NULL, 0);
        if (i < 0) {
            /* Should we try again? */
            if (errno == EWOULDBLOCK || errno == EAGAIN || errno == ENOBUFS ||
                errno == EINTR)
                return;

            /* In this case, we need to re-connect. */
            i = remote_reconnect(rr, errno);
            if (i == 0)
                return;

            /* Do a full reset. */
            remote_shutdown(rr, i);
            return;
        }

        /* SOCK_STREAM permits partial writes. */
        if (rr->info->ai_socktype == SOCK_STREAM)
            r->sent += i;
        else if (i == (int)tmp->length)
            r->sent = i;

        /* If the packet was completely sent, set a timeout. */
        if (r->sent == tmp->length) {
            verto_del(r->timer);
            r->timer = verto_add_timeout(rr->vctx, VERTO_EV_FLAG_NONE,
                                         on_timeout, r->timeout);
            if (r->timer == NULL)
                request_finish(r, ENOMEM, NULL);
            else
                verto_set_private(r->timer, r, NULL);
        }

        return;
    }

    verto_set_flags(rr->io, FLAGS_READ);
}

/* Read data from the socket. */
static void
on_io_read(krad_remote *rr)
{
    const krad_packet *req = NULL;
    krad_packet *rsp = NULL;
    krb5_error_code retval;
    ssize_t pktlen;
    request *tmp, *r;
    int i;

    pktlen = sizeof(rr->buffer_);
    if (rr->info->ai_socktype == SOCK_STREAM) {
        pktlen = krad_packet_bytes_needed(&rr->buffer);
        if (pktlen < 0) {
            retval = remote_reconnect(rr, EBADMSG);
            if (retval != 0)
                remote_shutdown(rr, retval);
            return;
        }
    }

    /* Read the packet. */
    i = recv(verto_get_fd(rr->io), rr->buffer.data + rr->buffer.length,
             pktlen - rr->buffer.length, 0);
    if (i < 0) {
        /* Should we try again? */
        if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
            return;

        if (errno == ECONNREFUSED || errno == ECONNRESET ||
            errno == ENOTCONN) {
            /*
             * When doing UDP against a local socket, the kernel will notify
             * when the daemon closes. But not against remote sockets. We want
             * to treat them both the same. Returning here will cause an
             * eventual timeout.
             */
            if (rr->info->ai_socktype != SOCK_STREAM)
                return;
        }

        /* In this case, we need to re-connect. */
        i = remote_reconnect(rr, errno);
        if (i == 0)
           return;

        /* Do a full reset. */
        remote_shutdown(rr, i);
        return;
    }

    /* If we have a partial read or just the header, try again. */
    rr->buffer.length += i;
    pktlen = krad_packet_bytes_needed(&rr->buffer);
    if (rr->info->ai_socktype == SOCK_STREAM && pktlen > 0)
        return;

    /* Decode the packet. */
    tmp = TAILQ_FIRST(&rr->list);
    retval = krad_packet_decode_response(rr->kctx, rr->secret, &rr->buffer,
                                         (krad_packet_iter_cb)iterator, &tmp,
                                         &req, &rsp);
    rr->buffer.length = 0;
    if (retval != 0)
        return;

    /* Match the response with an outstanding request. */
    if (req != NULL) {
        TAILQ_FOREACH(r, &rr->list, list) {
            if (r->request == req &&
                r->sent == krad_packet_encode(req)->length) {
                request_finish(r, 0, rsp);
                break;
            }
        }
    }

    krad_packet_free(rsp);
}

/* Handle when IO is ready on the socket. */
static void
on_io(verto_ctx *ctx, verto_ev *ev)
{
    krad_remote *rr;

    rr = verto_get_private(ev);

    if (verto_get_fd_state(ev) & VERTO_EV_FLAG_IO_WRITE)
        on_io_write(rr);
    else
        on_io_read(rr);
}

krb5_error_code
kr_remote_new(krb5_context kctx, verto_ctx *vctx, const struct addrinfo *info,
              const char *secret, krad_remote **rr)
{
    krb5_error_code retval = ENOMEM;
    krad_remote *tmp = NULL;

    tmp = calloc(1, sizeof(krad_remote));
    if (tmp == NULL)
        goto error;
    tmp->kctx = kctx;
    tmp->vctx = vctx;
    tmp->buffer = make_data(tmp->buffer_, 0);
    TAILQ_INIT(&tmp->list);

    tmp->secret = strdup(secret);
    if (tmp->secret == NULL)
        goto error;

    tmp->info = k5memdup(info, sizeof(*info), &retval);
    if (tmp->info == NULL)
        goto error;

    tmp->info->ai_addr = k5memdup(info->ai_addr, info->ai_addrlen, &retval);
    if (tmp->info == NULL)
        goto error;
    tmp->info->ai_next = NULL;
    tmp->info->ai_canonname = NULL;

    retval = remote_connect(tmp);
    if (retval != 0)
        goto error;

    *rr = tmp;
    return 0;

error:
    kr_remote_free(tmp);
    return retval;
}

void
kr_remote_free(krad_remote *rr)
{
    if (rr == NULL)
        return;

    while (!TAILQ_EMPTY(&rr->list))
        request_finish(TAILQ_FIRST(&rr->list), ECANCELED, NULL);

    free(rr->secret);
    if (rr->info != NULL)
        free(rr->info->ai_addr);
    free(rr->info);
    verto_del(rr->io);
    free(rr);
}

krb5_error_code
kr_remote_send(krad_remote *rr, krad_code code, krad_attrset *attrs,
               krad_cb cb, void *data, time_t timeout, size_t retries,
               const krad_packet **pkt)
{
    krad_packet *tmp = NULL;
    krb5_error_code retval;
    request *r;

    r = TAILQ_FIRST(&rr->list);
    retval = krad_packet_new_request(rr->kctx, rr->secret, code, attrs,
                                     (krad_packet_iter_cb)iterator, &r, &tmp);
    if (retval != 0)
        goto error;

    TAILQ_FOREACH(r, &rr->list, list) {
        if (r->request == tmp) {
            retval = EALREADY;
            goto error;
        }
    }

    if (rr->io == NULL) {
        retval = remote_connect(rr);
        if (retval != 0)
            goto error;
    }

    if (rr->info->ai_socktype == SOCK_STREAM)
        retries = 0;
    timeout = timeout / (retries + 1);
    retval = request_new(rr, tmp, timeout, retries, cb, data, &r);
    if (retval != 0)
        goto error;

    if ((verto_get_flags(rr->io) & VERTO_EV_FLAG_IO_WRITE) == 0)
        verto_set_flags(rr->io, FLAGS_WRITE);

    TAILQ_INSERT_TAIL(&rr->list, r, list);
    if (pkt != NULL)
        *pkt = tmp;
    return 0;

error:
    krad_packet_free(tmp);
    return retval;
}

void
kr_remote_cancel(krad_remote *rr, const krad_packet *pkt)
{
    request *r;

    TAILQ_FOREACH(r, &rr->list, list) {
        if (r->request == pkt) {
            request_finish(r, ECANCELED, NULL);
            return;
        }
    }
}

krb5_boolean
kr_remote_equals(const krad_remote *rr, const struct addrinfo *info,
                 const char *secret)
{
    struct sockaddr_un *a, *b;

    if (strcmp(rr->secret, secret) != 0)
        return FALSE;

    if (info->ai_addrlen != rr->info->ai_addrlen)
        return FALSE;

    if (info->ai_family != rr->info->ai_family)
        return FALSE;

    if (info->ai_socktype != rr->info->ai_socktype)
        return FALSE;

    if (info->ai_protocol != rr->info->ai_protocol)
        return FALSE;

    if (info->ai_flags != rr->info->ai_flags)
        return FALSE;

    if (memcmp(rr->info->ai_addr, info->ai_addr, info->ai_addrlen) != 0) {
        /* AF_UNIX fails the memcmp() test due to uninitialized bytes after the
         * socket name. */
        if (info->ai_family != AF_UNIX)
            return FALSE;

        a = (struct sockaddr_un *)info->ai_addr;
        b = (struct sockaddr_un *)rr->info->ai_addr;
        if (strncmp(a->sun_path, b->sun_path, sizeof(a->sun_path)) != 0)
            return FALSE;
    }

    return TRUE;
}
