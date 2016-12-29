# This class provides a common base for both the client and server
# portions of an OpenLDAP-based sysetm.
#
# @param ldap_master_uri
#   This is the LDAP master if there is one.
#
# @param ldap_uri
#   It is recommended that you make the master the last entry in this
#   array.
#
# @param is_server
#   Set this if you want to create an OpenLDAP server on your node.
#
# @param sssd
#   Whether or not to use SSSD in the installation.
#
# == Hiera Variables
#
# @param ldap::base_dn
#   The Base DN of the LDAP server.
#
# @param ldap::bind_dn
#   The credentials to use when binding to the LDAP server.
#
# @param ldap::master
#   The LDAP Master (optional)
#
# @param ldap::uri
#   An Array of OpenLDAP servers in URI form (ldap://server)
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
#
class openldap (
  Array[Simplib::URI]  $ldap_uri            = simplib::lookup('simp_options::ldap::uri', { 'default_value' => ["ldap://${hiera('simp_options::puppet::server')}"] } ),
  String               $base_dn             = simplib::lookup('simp_options::ldap::base_dn', { 'default_value' => '' }),
  String               $bind_dn             = simplib::lookup('simp_options::ldap::bind_dn', { 'default_value' => "cn=hostAuth,ou=Hosts,%{hiera('simp_options::ldap::base_dn')}" }),
  String               $ldap_master         = simplib::lookup('simp_options::ldap::master', { 'default_value' => "ldap://${hiera('simp_options::puppet::server')}" }),
  Boolean              $is_server           = false,
  Boolean              $sssd                = simplib::lookup('simp_options::sssd', { 'default_value' => false }),
  Stdlib::Absolutepath $app_pki_dir         = '/etc/openldap',
  Stdlib::Absolutepath $app_pki_cert_source = simplib::lookup('simp_options::pki::source', { 'default_value' => '/etc/pki/simp' })
) {

  if $is_server {
    include '::openldap::server'
  }
}
