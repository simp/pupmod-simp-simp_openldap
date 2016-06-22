# Class: openldap::slapo::ppolicy
#
# Configure the password policy for a site.
#
# See slapo-ppolicy(5) for details of any option not defined below.
#
# This also includes the options for configuring the password checking plugin
# that's included with SIMP.
#
# == Parameters:
#
# [*suffix*]
# Type: LDAP DN
# Default: hiera('ldap::base_dn')
#   The Base DN of the LDAP domain to which you wish to connect.
#
# [*min_points*]
# Type: Integer
# Default: '3'
#   The minimum number of character classes that must be included in your
#   password for it to succeed.
#
# [*use_cracklib*]
# Type: Boolean
# Default: true
#   If true, use cracklib when checking the password.
#
# [*min_upper*]
# Type: Integer
# Default: '0'
#   The minimum number of upper case characters that must be present for the
#   password to be valid.
#
# [*min_lower*]
# Type: Integer
# Default: '0'
#   The minimum number of lower case characters that must be present for the
#   password to be valid.
#
# [*min_digit*]
# Type: Integer
# Default: '0'
#   The minimum number of digit characters that must be present for the
#   password to be valid.
#
# [*min_punct*]
# Type: Integer
# Default: '0'
#   The minimum number of punctuation characters that must be present for the
#   password to be valid.
#
# [*max_consecutive_per_class*]
# Type: Integer
# Default: '2'
#   The maximum number of characters from any character class that can exist in
#   a row.
#
# == Authors
#
# * Trevor Vaughan <tvaughan@onyxpoint.com>
#
class openldap::slapo::ppolicy (
    $suffix = hiera('ldap::base_dn'),
    $ppolicy_default='',
    $ppolicy_hash_cleartext='',
    $ppolicy_use_lockout='',
    $min_points = '3',
    $use_cracklib = true,
    $min_upper = '0',
    $min_lower = '0',
    $min_digit = '0',
    $min_punct = '0',
    $max_consecutive_per_class = '2'
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
    order   => '1000',
    content => template('openldap/slapo/ppolicy.erb')
  }

  file { "/etc/openldap/${check_password}.conf":
    owner   => 'root',
    group   => 'ldap',
    mode    => '0640',
    content => template('openldap/etc/openldap/check_password.conf.erb')
  }
}
