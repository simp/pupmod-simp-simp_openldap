# **NOTE: THIS IS A [PRIVATE](https://github.com/puppetlabs/puppetlabs-stdlib#assert_private) CLASS**
#
# This allows for the modification of the default LDIF entries in
# /etc/openldap/default.ldif. It will **not** modify any active values in a
# running LDAP server.
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
#
class simp_openldap::server::conf::default_ldif (
  Integer[1]   $users_group_id                     = 100,
  Integer[500] $administrators_group_id            = 700,
  Integer[0]   $ppolicy_pwd_min_age                = 86400,
  Integer[1]   $ppolicy_pwd_max_age                = 15552000,
  Integer[0]   $ppolicy_pwd_in_history             = 24,
  Integer[0]   $ppolicy_pwd_check_quality          = 2,
  Integer[0]   $ppolicy_pwd_min_length             = 14,
  Integer[0]   $ppolicy_pwd_expire_warning         = 1209600,
  Integer      $ppolicy_pwd_grace_authn_limit      = -1,
  Boolean      $ppolicy_pwd_lockout                = true,
  Integer[0]   $ppolicy_pwd_lockout_duration       = 900,
  Integer[0]   $ppolicy_pwd_max_failure            = 5,
  Integer[0]   $ppolicy_pwd_failure_count_interval = 900,
  Boolean      $ppolicy_pwd_must_change            = true,
  Boolean      $ppolicy_pwd_allow_user_change      = true,
  Boolean      $ppolicy_pwd_safe_modify            = false
) {

  assert_private()

  $_suffix = $::simp_openldap::server::conf::suffix
  $_rootdn = $::simp_openldap::server::conf::rootdn
  $_syncdn = $::simp_openldap::server::conf::syncdn
  $_syncpw = $::simp_openldap::server::conf::syncpw
  $_binddn = $::simp_openldap::server::conf::binddn
  $_bindpw = $::simp_openldap::server::conf::bindpw

  if (
    defined('$::simp_openldap::slapo::ppolicy::_check_password') and
    getvar('::simp_openldap::slapo::ppolicy::_check_password')
  ) {
    $_simp_ppolicy_check_password = getvar('::simp_openldap::slapo::ppolicy::_check_password')
  }
  else {
    $_simp_ppolicy_check_password = undef
  }

  file { '/etc/openldap/default.ldif':
    ensure  => 'file',
    owner   => 'root',
    group   => 'ldap',
    mode    => '0640',
    content => template("${module_name}/etc/openldap/default.ldif.erb")
  }
}
