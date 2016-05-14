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
# [*use_nscd*]
# Type: Boolean
# Default: true
#   Only appiles to *client* systems
#
#   Whether or not to use NSCD in the installation instead of SSSD. If
#   '$use_sssd = true' then this will not be referenced.
#
# [*use_sssd*]
# Type: Boolean
# Default: false if EL<7, true otherwise
#   Only appiles to *client* systems
#
#   Whether or not to use SSSD in the installation.
#   There are issues where SSSD will allow a login, even if the user's password
#   has expire, if the user has a valid SSH key. However, in EL7+, there are
#   issues with nscd and nslcd which can lock users our of the system when
#   using LDAP.
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
  $use_nscd = $::openldap::params::use_nscd,
  $use_sssd = $::openldap::params::use_sssd
) inherits ::openldap::params {
  if $is_server { include '::openldap::server' }

  validate_bool($is_server)
}
