# @summary Install the required packages
#
# @param ensure
#   The state for the packages to be in
#
# @api private
# @author https://github.com/simp/pupmod-simp-simp_openldap/graphs/contributors
#
class simp_openldap::server::install (
  Enum['latest','installed','present'] $ensure = simplib::lookup('simp_options::package_ensure', { 'default_value' => 'installed' }),
){
  package { 'openldap':
    ensure => $ensure
  }
  package { "openldap-servers.${facts['os']['hardware']}":
    ensure => $ensure
  }
}
