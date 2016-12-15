#
# == Class: openldap::server::conf::default_ldif
#
# This allows for the modification of the default LDIF entries in
# /etc/openldap/default.ldif. It will *not* modify any active values in a
# running LDAP server.
#
# == Authors:
#
# * Trevor Vaughan <tvaughan@onyxpoint.com>
#
class openldap::server::conf::default_ldif (
  Integer   $ppolicy_pwd_min_age                = 86400,
  Integer   $ppolicy_pwd_max_age                = 15552000,
  Integer   $ppolicy_pwd_in_history             = 24,
  Integer   $ppolicy_pwd_check_quality          = 2,
  Integer   $ppolicy_pwd_min_length             = 14,
  Integer   $ppolicy_pwd_expire_warning         = 1209600,
  Integer   $ppolicy_pwd_grace_authn_limit      = -1,
  Boolean   $ppolicy_pwd_lockout                = true,
  Integer   $ppolicy_pwd_lockout_duration       = 900,
  Integer   $ppolicy_pwd_max_failure            = 5,
  Integer   $ppolicy_pwd_failure_count_interval = 900,
  Boolean   $ppolicy_pwd_must_change            = true,
  Boolean   $ppolicy_pwd_allow_user_change      = true,
  Boolean   $ppolicy_pwd_safe_modify            = false
) {

  assert_private()

  $_suffix = $::openldap::server::conf::suffix
  $_rootdn = $::openldap::server::conf::rootdn
  $_syncdn = $::openldap::server::conf::syncdn
  $_syncpw = $::openldap::server::conf::syncpw
  $_binddn = $::openldap::server::conf::binddn
  $_bindpw = $::openldap::server::conf::bindpw

  if ( defined('$::openldap::slapo::ppolicy::check_password') and
      getvar('::openldap::slapo::ppolicy::check_password') and
      !empty(getvar('::openldap::slapo::ppolicy::check_password'))
  ) {
    $_simp_ppolicy_check_password = $::openldap::slapo::ppolicy::check_password
  }
  else {
    $_simp_ppolicy_check_password = false
  }

  file { '/etc/openldap/default.ldif':
    ensure  => 'file',
    owner   => 'root',
    group   => 'ldap',
    mode    => '0640',
    content => template('openldap/etc/openldap/default.ldif.erb'),
  }
}
