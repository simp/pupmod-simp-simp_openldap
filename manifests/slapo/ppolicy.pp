# Configure the password policy for a site.
#
# See slapo-ppolicy(5) for details of any option not defined below.
#
# This also includes the options for configuring the password checking plugin
# that's included with SIMP.
#
# @param suffix
#   The Base DN of the LDAP domain to which you wish to connect.
#
# @param min_points
#   The minimum number of character classes that must be included in your
#   password for it to succeed.
#
# @param use_cracklib
#   If true, use cracklib when checking the password.
#
# @param min_upper
#   The minimum number of upper case characters that must be present for the
#   password to be valid.
#
# @param min_lower
#   The minimum number of lower case characters that must be present for the
#   password to be valid.
#
# @param min_digit
#   The minimum number of digit characters that must be present for the
#   password to be valid.
#
# @param min_punct
#   The minimum number of punctuation characters that must be present for the
#   password to be valid.
#
# @param max_consecutive_per_class
#   The maximum number of characters from any character class that can exist in
#   a row.
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
#
class openldap::slapo::ppolicy (
    String    $suffix                    = simplib::lookup('simp_options::ldap::basedn', { 'default_value' => "" }),
    String    $ppolicy_default           = '',
    String    $ppolicy_hash_cleartext    = '',
    String    $ppolicy_use_lockout       = '',
    Integer   $min_points                = 3,
    Boolean   $use_cracklib              = true,
    Integer   $min_upper                 = 0,
    Integer   $min_lower                 = 0,
    Integer   $min_digit                 = 0,
    Integer   $min_punct                 = 0,
    Integer   $max_consecutive_per_class = 3
) {
  include '::openldap::server::dynamic_includes'

  $_simp_version = simp_version() ? {
    /undefined/ => '0',
    default     => simp_version()
  }

  # This is used by the default template.
  # This should be cleaned up all around.
  $check_password = versioncmp($_simp_version, '4.2.0') ? {
    '-1'    => 'check_password',
    default => 'simp_check_password'
  }

  package { 'simp-ppolicy-check-password': ensure => 'latest' }

  openldap::server::dynamic_includes::add { 'ppolicy':
    order   => 1000,
    content => template('openldap/slapo/ppolicy.erb')
  }

  file { "/etc/openldap/${check_password}.conf":
    owner   => 'root',
    group   => 'ldap',
    mode    => '0640',
    content => template('openldap/etc/openldap/check_password.conf.erb')
  }
}
