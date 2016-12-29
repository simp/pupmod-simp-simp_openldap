# This is a helper class for adding dynamic includes to the slapd server.
#
class openldap::server::dynamic_includes {
  include '::openldap::server'

  simpcat_build { 'slapd_dynamic_includes':
    order  => '*.inc',
    target => '/etc/openldap/dynamic_includes',
    before => Exec['bootstrap_ldap']
  }
}
