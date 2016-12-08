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
# [*use_sssd*]
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
  $ldap_uri = simplib::lookup('simp_options::ldap::uri', { 'default_value' => ["ldap://${hiera('simp_options::puppet::server')}"], 'value_type' => Array } ),
  $base_dn = simplib::lookup('simp_options::ldap::base_dn', { 'value_type' => String }),
  $bind_dn = simplib::lookup('simp_options::ldap::bind_dn', { 'default_value' => "cn=hostAuth,ou=Hosts,%{hiera('simp_options::ldap::base_dn')}", 'value_type' => String }),
  $ldap_master = simplib::lookup('simp_options::ldap::master', { 'default_value' => "ldap://${hiera('simp_options::puppet::server')}", 'value_type' => String }),
  $is_server = false,
  $use_sssd = simplib::lookup('simp_options::sssd', { 'default_value' => false, 'value_type' => Boolean }),
) {
  if $is_server { include '::openldap::server' }

  validate_bool($is_server)
}
