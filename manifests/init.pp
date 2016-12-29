# == Class: openldap
#
# This class provides a common base for both the client and server
# portions of an OpenLDAP-based sysetm.
#
# == Parameters
#
# [*ldap_master_uri*]
# Type: LDAP URI
#   This is the LDAP master if there is one.
#
# [*ldap_uri*]
# Type: Array of LDAP servers
#   It is recommended that you make the master the last entry in this
#   array.
#
# [*is_server*]
# Type: Boolean
# Default: false
#   Set this if you want to create an OpenLDAP server on your node.
#
#
# [*sssd*]
# Type: Boolean
# Default: false
#   Whether or not to use SSSD in the installation.
#
# == Hiera Variables
#
# [*ldap::base_dn*]
#   The Base DN of the LDAP server.
#
# [*ldap::bind_dn*]
#   The credentials to use when binding to the LDAP server.
#
# [*ldap::master*]
#   The LDAP Master (optional)
#
# [*ldap::uri*]
#   An Array of OpenLDAP servers in URI form (ldap://server)
#
# == Authors
#
#   * Trevor Vaughan <tvaughan@onyxpoint.com>
#
class openldap (
  Array[String]        $ldap_uri             = simplib::lookup('simp_options::ldap::uri', { 'default_value' => ["ldap://${hiera('simp_options::puppet::server')}"] } ),
  String               $base_dn              = simplib::lookup('simp_options::ldap::base_dn', { 'default_value' => '' }),
  String               $bind_dn              = simplib::lookup('simp_options::ldap::bind_dn', { 'default_value' => "cn=hostAuth,ou=Hosts,%{hiera('simp_options::ldap::base_dn')}" }),
  String               $ldap_master          = simplib::lookup('simp_options::ldap::master', { 'default_value' => "ldap://${hiera('simp_options::puppet::server')}" }),
  Boolean              $is_server            = false,
  Boolean              $sssd                 = simplib::lookup('simp_options::sssd', { 'default_value' => false }),
  Stdlib::Absolutepath $app_pki_dir          = '/etc/openldap',
  Stdlib::Absolutepath $app_pki_cert_source  = simplib::lookup('simp_options::pki::source', { 'default_value' => '/etc/pki/simp' })
) {

  validate_uri_list($ldap_uri)

  if $is_server {
    include '::openldap::server'
  }
}
