from k5test import *

realm = K5Realm(get_creds=False)
del realm.env['KRB5CCNAME']

s_klist = '/usr/bin/klist'
s_kinit = '/usr/bin/kinit'
realm.run([klist], expected_code=1)
realm.run([s_klist], expected_code=1)

realm.kinit(realm.user_princ, password('user'))
realm.run([klist])
realm.run([s_klist])

realm.kinit(realm.admin_princ, password('admin'))
realm.run([klist])
realm.run([klist, '-l'])
realm.run([s_klist])
realm.run([s_klist, '-l'])

realm.run([kswitch, '-p', 'user'])
realm.run([klist])
realm.run([klist, '-l'])
realm.run([s_klist, '-l'])

realm.run([kdestroy, '-A'])

realm.env['KRB5CCNAME'] = 'API:11111111-71F2-48EB-94C4-7D7392E900E6'
realm.run([klist], expected_code=1)
