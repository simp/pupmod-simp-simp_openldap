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
# @param pki
#   * If 'simp', include SIMP's pki module and use pki::copy to manage
#     application certs in /etc/pki/simp_apps/openldap/x509
#   * If true, do *not* include SIMP's pki module, but still use pki::copy
#     to manage certs in /etc/pki/simp_apps/openldap/x509
#   * If false, do not include SIMP's pki module and do not use pki::copy
#     to manage certs.  You will need to appropriately assign a subset of:
#     * app_pki_dir
#     * app_pki_key
#     * app_pki_cert
#     * app_pki_ca
#     * app_pki_ca_dir
#
# @param app_pki_external_source
#   * If pki = 'simp' or true, this is the directory from which certs will be
#     copied, via pki::copy.  Defaults to /etc/pki/simp/x509.
#
#   * If pki = false, this variable has no effect.
#
# @param app_pki_dir
#   This variable controls the basepath of $app_pki_key, $app_pki_cert,
#   $app_pki_ca, $app_pki_ca_dir, and $app_pki_crl.
#   It defaults to /etc/pki/simp_apps/openldap/x509.
#
# @param app_pki_key
#   Path and name of the private SSL key file.
#
# @param app_pki_cert
#   Path and name of the public SSL certificate.
#
# @param app_pki_ca_dir
#   Path to the CA.
#
# @param app_pki_crl
#   Path to the CRL file.
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
#
class simp_openldap (
  Array[Simplib::URI]            $ldap_uri                = simplib::lookup('simp_options::ldap::uri', { 'default_value' => undef }),
  String                         $base_dn                 = simplib::lookup('simp_options::ldap::base_dn', { 'default_value' => simplib::ldap::domain_to_dn() }),
  String                         $bind_dn                 = simplib::lookup('simp_options::ldap::bind_dn', { 'default_value' => sprintf('cn=hostAuth,ou=Hosts,%s', simplib::ldap::domain_to_dn()) }),
  String                         $ldap_master             = simplib::lookup('simp_options::ldap::master', { 'default_value'  => undef }),
  Boolean                        $is_server               = false,
  Boolean                        $sssd                    = simplib::lookup('simp_options::sssd', { 'default_value' => false }),
  Variant[Boolean, Enum['simp']] $pki                     = simplib::lookup('simp_options::pki', { 'default_value' => false }),
  String                         $app_pki_external_source = simplib::lookup('simp_options::pki::source', { 'default_value' => '/etc/pki/simp/x509' }),
  Stdlib::Absolutepath           $app_pki_dir             = '/etc/pki/simp_apps/openldap/x509',
  Stdlib::AbsolutePath           $app_pki_cert            = "${app_pki_dir}/public/${facts['fqdn']}.pub",
  Stdlib::AbsolutePath           $app_pki_key             = "${app_pki_dir}/private/${facts['fqdn']}.pem",
  Stdlib::AbsolutePath           $app_pki_ca_dir          = "${app_pki_dir}/cacerts",
  Optional[Stdlib::Absolutepath] $app_pki_crl             = undef,
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
    contain '::simp_openldap::server'
  }

  contain '::simp_openldap::client'

  if $pki {
    pki::copy { 'openldap':
      source => $app_pki_external_source,
      pki    => $pki,
      group  => 'ldap'
    }
  }
}
