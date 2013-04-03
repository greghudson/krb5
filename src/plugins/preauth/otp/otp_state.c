/*
 * Copyright 2012 Red Hat, Inc.  All rights reserved.
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

#include "otp_state.h"

#include <krad.h>
#include <k5-json.h>

#include <ctype.h>

#ifndef HOST_NAME_MAX
/* SUSv2 */
#define HOST_NAME_MAX 255
#endif

typedef struct token_type_ {
    char *name;
    char *server;
    char *secret;
    time_t timeout;
    size_t retries;
    krb5_boolean strip_realm;
} token_type;

typedef struct token_ {
    const token_type *type;
    krb5_data username;
} token;

typedef struct request_ {
    otp_state *state;
    token *tokens;
    ssize_t index;
    otp_cb *cb;
    void *data;
    krad_attrset *attrs;
} request;

struct otp_state_ {
    krb5_context ctx;
    token_type *types;
    krad_client *radius;
    krad_attrset *attrs;
};

static inline krb5_data
string2data_copy(const char *s)
{
    char *tmp;

    tmp = strdup(s);
    return make_data(NULL, tmp == NULL ? 0 : strlen(tmp));
}

/* Free a NULL-terminated array of strings. */
static void
stringv_free(char **strv)
{
    size_t i;

    if (strv == NULL)
        return;

    for (i = 0; strv[i] != NULL; i++)
        free(strv[i]);

    free(strv);
}

/* Free the contents of a single token type. */
static void
token_type_free(token_type *type)
{
    if (type == NULL)
        return;

    free(type->name);
    free(type->server);
    free(type->secret);
}

/* Decode a single token type from the profile. */
static krb5_error_code
token_type_decode(profile_t profile, const char *name, token_type *out)
{
    krb5_error_code retval;
    char *defsrv = NULL;
    token_type tt;
    int tmp;

    memset(&tt, 0, sizeof(tt));

    /* Set the name. */
    tt.name = strdup(name == NULL ? "DEFAULT" : name);
    if (tt.name == NULL) {
        retval = ENOMEM;
        goto error;
    }

    /* Set defaults. */
    tt.timeout = 5000;
    tt.retries = 3;
    if (asprintf(&defsrv, "%s/%s.socket", KDC_DIR, tt.name) < 0) {
        retval = ENOMEM;
        goto error;
    }

    /* Set the internal default. */
    if (name == NULL) {
        retval = ENOMEM;

        tt.secret = strdup("");
        if (tt.secret == NULL)
            goto error;

        tt.server = defsrv;
        tt.strip_realm = FALSE;

        *out = tt;
        return 0;
    }

    /* Set strip_realm. */
    retval = profile_get_boolean(profile, "otp", name, "strip_realm", TRUE,
                                 &tmp);
    if (retval != 0)
        goto error;
    tt.strip_realm = tmp == 0 ? FALSE : TRUE;

    /* Set the server. */
    retval = profile_get_string(profile, "otp", name, "server",
                                defsrv, &tt.server);
    if (retval != 0)
        goto error;

    /* Set the secret. */
    retval = profile_get_string(profile, "otp", name, "secret",
                                tt.server[0] == '/' ? "" : NULL,
                                &tt.server);
    if (retval != 0) {
        goto error;
    } else if (tt.secret == NULL) {
        DEBUGMSG(EINVAL, "Secret not specified in token type '%s'.", name);
        retval = EINVAL;
        goto error;
    }

    /* Set the timeout. */
    retval = profile_get_integer(profile, "otp", name, "timeout",
                                 tt.timeout / 1000, &tmp);
    if (retval != 0)
        goto error;
    tt.timeout = tmp * 1000; /* Convert to milliseconds. */

    /* Set the retries. */
    retval = profile_get_integer(profile, "otp", name, "retries",
                                 tt.retries, &tmp);
    if (retval != 0)
        goto error;
    tt.retries = tmp;

    *out = tt;
    free(defsrv);
    return 0;

error:
    token_type_free(&tt);
    free(defsrv);
    return retval;
}

/* Free an array of token types. */
static void
token_types_free(token_type *types)
{
    size_t i;

    if (types == NULL)
        return;

    for (i = 0; types[i].server != NULL; i++)
        token_type_free(&types[i]);

    free(types);
}

/* Decode an array of token types from the profile. */
static krb5_error_code
token_types_decode(profile_t profile, token_type **out)
{
    const char *tmp[2] = { "otp", NULL };
    token_type *types = NULL;
    char **names = NULL;
    errcode_t retval;
    ssize_t i, j;

    retval = profile_get_subsection_names(profile, tmp, &names);
    if (retval != 0)
        return retval;

    for (i = 0, j = 0; names[i] != NULL; i++) {
        if (strcmp(names[i], "DEFAULT") == 0)
            j = 1;
    }

    types = calloc(i - j + 2, sizeof(token_type));
    if (types == NULL) {
        retval = ENOMEM;
        goto error;
    }

    /* If no default has been specified, use our internal default. */
    if (j == 0) {
        retval = token_type_decode(profile, NULL, &types[j++]);
        if (retval != 0)
            goto error;
    } else {
        j = 0;
    }

    for (i = 0; names[i] != NULL; i++) {
        retval = token_type_decode(profile, names[i], &types[j++]);
        if (retval != 0)
            goto error;
    }

    stringv_free(names);
    *out = types;
    return 0;

error:
    token_types_free(types);
    stringv_free(names);
    return retval;
}

/* Free the contents of a single token. */
static void
token_free(token *t)
{
    if (t == NULL)
        return;

    free(t->username.data);
}

/* Decode a single token from a JSON token object. */
static krb5_error_code
token_decode(krb5_context ctx, krb5_const_principal princ,
             const token_type *types, k5_json_object obj, token *out)
{
    const char *type = NULL;
    krb5_error_code retval;
    k5_json_value tmp;
    size_t i;
    token t;

    memset(&t, 0, sizeof(t));

    tmp = k5_json_object_get(obj, "username");
    if (tmp != NULL && k5_json_get_tid(tmp) == K5_JSON_TID_STRING) {
        t.username = string2data_copy(k5_json_string_utf8(tmp));
        if (t.username.data == NULL)
            return ENOMEM;
    }

    tmp = k5_json_object_get(obj, "type");
    if (tmp != NULL && k5_json_get_tid(tmp) == K5_JSON_TID_STRING)
        type = k5_json_string_utf8(tmp);

    for (i = 0; types[i].server != NULL; i++) {
        if (strcmp(type == NULL ? "DEFAULT" : type, types[i].name) == 0)
            t.type = &types[i];
    }

    if (t.username.data == NULL) {
        retval = krb5_unparse_name_flags(ctx, princ,
                                         t.type->strip_realm
                                             ? KRB5_PRINCIPAL_UNPARSE_NO_REALM
                                             : 0,
                                         &t.username.data);
        if (retval != 0)
            return retval;
        t.username.length = strlen(t.username.data);
    }

    *out = t;
    return 0;
}

/* Free an array of tokens. */
static void
tokens_free(token *tokens)
{
    size_t i;

    if (tokens == NULL)
        return;

    for (i = 0; tokens[i].type != NULL; i++)
        token_free(&tokens[i]);

    free(tokens);
}

/* Decode an array of tokens from the configuration string. */
static krb5_error_code
tokens_decode(krb5_context ctx, krb5_const_principal princ,
              const token_type *types, const char *config, token **out)
{
    krb5_error_code retval;
    k5_json_value arr, obj;
    token *tokens;
    ssize_t len, i, j;

    if (config == NULL)
        config = "[{}]";

    retval = k5_json_decode(config, &arr);
    if (retval != 0)
        return retval;

    if (k5_json_get_tid(arr) != K5_JSON_TID_ARRAY ||
        (len = k5_json_array_length(arr)) == 0) {
        k5_json_release(arr);

        retval = k5_json_decode("[{}]", &arr);
        if (retval != 0)
            return retval;

        if (k5_json_get_tid(arr) != K5_JSON_TID_ARRAY) {
            k5_json_release(arr);
            return ENOMEM;
        }

        len = k5_json_array_length(arr);
    }

    tokens = calloc(len + 1, sizeof(token));
    if (tokens == NULL) {
        k5_json_release(arr);
        return ENOMEM;
    }

    for (i = 0, j = 0; i < len; i++) {
        obj = k5_json_array_get(arr, i);
        if (k5_json_get_tid(obj) != K5_JSON_TID_OBJECT)
            continue;

        retval = token_decode(ctx, princ, types, obj, &tokens[j++]);
        if (retval != 0) {
            k5_json_release(arr);
            while (--j > 0)
                token_free(&tokens[j]);
            free(tokens);
            return retval;
        }
    }

    k5_json_release(arr);
    *out = tokens;
    return 0;
}

static void
request_free(request *req)
{
    if (req == NULL)
        return;

    krad_attrset_free(req->attrs);
    tokens_free(req->tokens);
    free(req);
}

krb5_error_code
otp_state_new(krb5_context ctx, otp_state **out)
{
    char hostname[HOST_NAME_MAX + 1];
    krb5_error_code retval;
    profile_t profile;
    krb5_data hndata;
    otp_state *self;

    retval = gethostname(hostname, sizeof(hostname));
    if (retval != 0)
        return retval;

    self = calloc(1, sizeof(otp_state));
    if (self == NULL)
        return ENOMEM;

    retval = krb5_get_profile(ctx, &profile);
    if (retval != 0)
        goto error;

    retval = token_types_decode(profile, &self->types);
    profile_abandon(profile);
    if (retval != 0)
        goto error;

    retval = krad_attrset_new(ctx, &self->attrs);
    if (retval != 0)
        goto error;

    hndata = make_data(hostname, strlen(hostname));
    retval = krad_attrset_add(self->attrs,
                              krad_attr_name2num("NAS-Identifier"), &hndata);
    if (retval != 0)
        goto error;

    retval = krad_attrset_add_number(self->attrs,
                                     krad_attr_name2num("Service-Type"),
                                     KRAD_SERVICE_TYPE_AUTHENTICATE_ONLY);
    if (retval != 0)
        goto error;

    self->ctx = ctx;
    *out = self;
    return 0;

error:
    otp_state_free(self);
    return retval;
}

void
otp_state_free(otp_state *self)
{
    if (self == NULL)
        return;

    krad_attrset_free(self->attrs);
    token_types_free(self->types);
    free(self);
}

static void
request_send(request *req);

static void
callback(krb5_error_code retval, const krad_packet *rqst,
         const krad_packet *resp, void *data)
{
    request *req = data;

    req->index++;

    if (retval != 0)
        goto error;

    /* If we received an accept packet, success! */
    if (krad_packet_get_code(resp) ==
        krad_code_name2num("Access-Accept")) {
        (*req->cb)(retval, otp_response_success, req->data);
        request_free(req);
        return;
    }

    /* If we have no more tokens to try, failure! */
    if (req->tokens[req->index].type == NULL)
        goto error;

    /* Try the next token. */
    request_send(req);

error:
    (*req->cb)(retval, otp_response_fail, req->data);
    request_free(req);
}

static void
request_send(request *req)
{
    krb5_error_code retval;

    retval = krad_attrset_add(req->attrs,
                                   krad_attr_name2num("User-Name"),
                                   &req->tokens[req->index].username);
    if (retval != 0)
        goto error;

    retval = krad_client_send(req->state->radius,
                              krad_code_name2num("Access-Request"), req->attrs,
                              req->tokens[req->index].type->server,
                              req->tokens[req->index].type->secret,
                              req->tokens[req->index].type->timeout,
                              req->tokens[req->index].type->retries,
                              callback, req);
    krad_attrset_del(req->attrs, krad_attr_name2num("User-Name"), 0);
    if (retval != 0)
        goto error;

    return;

error:
    (*req->cb)(retval, otp_response_fail, req->data);
    request_free(req);
}

void
otp_state_verify(otp_state *state, verto_ctx *ctx, krb5_const_principal princ,
                 const char *config, const krb5_pa_otp_req *req,
                 otp_cb *cb, void *data)
{
    krb5_error_code retval;
    request *rqst = NULL;

    if (state->radius == NULL) {
        retval = krad_client_new(state->ctx, ctx, &state->radius);
        if (retval != 0)
            goto error;
    }

    rqst = calloc(1, sizeof(request));
    if (rqst == NULL) {
        (*cb)(ENOMEM, otp_response_fail, data);
        return;
    }
    rqst->state = state;
    rqst->data = data;
    rqst->cb = cb;

    retval = krad_attrset_copy(state->attrs, &rqst->attrs);
    if (retval != 0)
        goto error;

    retval = krad_attrset_add(rqst->attrs, krad_attr_name2num("User-Password"),
                              &req->otp_value);
    if (retval != 0)
        goto error;

    retval = tokens_decode(state->ctx, princ, state->types, config,
                           &rqst->tokens);
    if (retval != 0)
        goto error;

    request_send(rqst);
    return;

error:
    (*cb)(retval, otp_response_fail, data);
    request_free(rqst);
}
