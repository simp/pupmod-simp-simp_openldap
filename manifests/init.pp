# This class provides a common base for both the client and server portions of
# an OpenLDAP-based sysetm
#
# @param ldap_uri
#   It is recommended that you make the master the last entry in this array
#
#   * Will default to ``["ldap://${server_facts['servername']}"]`` if not set
#
# @param base_dn
#   The base DN of the LDAP entries
#
# @param bind_dn
#   The use that should be used to bind to the LDAP server
#
# @param ldap_master
#   The LDAP Master server
#
#   * Will default to the **last** entry in ``ldap_uri`` if not set
#
# @param is_server
#   Set this if you want to create an OpenLDAP server on your node
#
# @param sssd
#   Whether or not to use SSSD in the installation
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
#
class openldap (
  Array[Simplib::URI]            $ldap_uri                = simplib::lookup('simp_options::ldap::uri', { 'default_value' => undef }),
  String                         $base_dn                 = simplib::lookup('simp_options::ldap::base_dn', { 'default_value' => openldap::domain_to_dn() }),
  String                         $bind_dn                 = simplib::lookup('simp_options::ldap::bind_dn', { 'default_value' => sprintf('cn=hostAuth,ou=Hosts,%s', openldap::domain_to_dn()) }),
  String                         $ldap_master             = simplib::lookup('simp_options::ldap::master', { 'default_value'  => undef }),
  Boolean                        $is_server               = false,
  Boolean                        $sssd                    = simplib::lookup('simp_options::sssd', { 'default_value' => false }),
  Variant[Boolean, Enum['simp']] $pki                     = simplib::lookup('simp_options::pki', { 'default_value' => false }),
  Stdlib::Absolutepath           $app_pki_dir             = '/etc/pki/simp_apps/openldap/pki',
  Stdlib::Absolutepath           $app_pki_external_source = simplib::lookup('simp_options::pki::source', { 'default_value' => '/etc/pki/simp' })
) {
  if $ldap_uri {
    $_ldap_uri = $ldap_uri
  }
  elsif $server_facts {
    $_ldap_uri = ["ldap://${server_facts['servername']}"]
  }
  else {
    fail('You must provide a value for `$ldap_uri`')
  }

  if $ldap_master {
    $_ldap_master = $ldap_master
  }
  else {
    $_ldap_master = $_ldap_uri[-1]
  }

  if $is_server {
    contain '::openldap::server'

    if $pki {
      Class['pki::copy'] ~> Class['openldap::server::service']
    }
  }

  contain '::openldap::client'

  if $pki {
    pki::copy { $module_name:
      group  => 'ldap',
      source => $app_pki_external_source,
      pki    => $pki
    }
  }
}
