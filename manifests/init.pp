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
  $base_dn = hiera('ldap::base_dn'),
  $bind_dn = hiera('ldap::bind_dn'),
  $ldap_master = hiera('ldap::master',''),
  $ldap_uri = hiera('ldap::uri'),
  $is_server = false,
) {

  include 'openldap::pam'

  if $is_server { include 'openldap::server' }

  validate_bool($is_server)
}
