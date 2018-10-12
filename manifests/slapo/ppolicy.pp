# Configure the password policy for a site
#
# @see slapo-ppolicy(5)
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
# @param ppolicy_ensure The ensure status of the simp-ppolicy-check-password
#   package
#
# @author https://github.com/simp/pupmod-simp-simp_openldap/graphs/contributors
#
class simp_openldap::slapo::ppolicy (
  Optional[String[1]] $suffix                    = $::simp_openldap::base_dn,
  Optional[String[1]] $ppolicy_default           = undef,
  Optional[String[1]] $ppolicy_hash_cleartext    = undef,
  Optional[String[1]] $ppolicy_use_lockout       = undef,
  Integer[0]          $min_points                = 3,
  Boolean             $use_cracklib              = true,
  Integer[0]          $min_upper                 = 0,
  Integer[0]          $min_lower                 = 0,
  Integer[0]          $min_digit                 = 0,
  Integer[0]          $min_punct                 = 0,
  Integer[0]          $max_consecutive_per_class = 3,
  String              $ppolicy_ensure            = simplib::lookup('simp_options::package_ensure', { 'default_value' => 'installed' }),
  ) inherits ::simp_openldap {
  $_check_password = 'simp_check_password'

  package { 'simp-ppolicy-check-password':
    ensure => $ppolicy_ensure
  }

  simp_openldap::server::dynamic_include { 'ppolicy':
    order   => 1000,
    content => template("${module_name}/slapo/ppolicy.erb")
  }

  file { "/etc/openldap/${_check_password}.conf":
    owner   => 'root',
    group   => 'ldap',
    mode    => '0640',
    content => template("${module_name}/etc/openldap/check_password.conf.erb")
  }
}
