# @summary Install the openldap-clients package and configure global options
# for accessing the LDAP servers.
#
# @see ldap.conf(5) for details.
#
# @param uri
#   LDAP servers
#
# @param base_dn
#   The base DN of the LDAP entries
#
# @param bind_dn
#   The user that should be used to bind to the LDAP server
#
# @param deref
#   How alias dereferencing is done when performing a search
#
# @param referrals
#   Whether the client should automatically follow referrals returned by LDAP servers
#
# @param sizelimit
#   Size limit (number of entries) to use when performing searches
#
# @param timelimit
#   Time limit (in seconds) to use when performing searches
#
# @param use_tls
#   Use TLS when connecting to the ldap server. By default this will mirror
#   simp_options::pki, but needs to be distinct as the client and server
#   configurations could vary.
#
# @param app_pki_key
#   Path and name of the private SSL key file
#
# @param app_pki_cert
#   Path and name of the public SSL certificate
#
# @param app_pki_ca_dir
#   Path to the CA.
#
# @param app_pki_crl
#   Path to the CRL file.
#
# @param strip_128_bit_ciphers
#   * **DEPRECATED**
#
# @param tls_cipher_suite
#   The default ciphers to use for TLS
#
# @param tls_crlcheck
#   Whether the Certificate Revocation List (CRL) of the CA should be used to
#   verify if the server certificates have not been revoked
#
# @param tls_reqcert
#  The checks to perform on server certificates in a TLS session
#
# @param openldap_clients_ensure
#   The ensure status of the openldap-clients package
#
# @param nss_pam_ldapd_ensure
#   **DEPRECATED** The nss-pam-ldapd package is no longer installed
#
class simp_openldap::client (
  Array[Simplib::URI]                          $uri                   = $simp_openldap::ldap_uri,
  Optional[String]                             $base_dn               = $simp_openldap::base_dn,
  String[1]                                    $bind_dn               = $simp_openldap::bind_dn,
  Enum['on','off']                             $referrals             = 'on',
  Integer                                      $sizelimit             = 0,
  Integer                                      $timelimit             = 15,
  Variant[Enum['simp'],Boolean]                $use_tls               = $simp_openldap::pki,
  Stdlib::Absolutepath                         $app_pki_ca_dir        = $simp_openldap::app_pki_ca_dir,
  Stdlib::Absolutepath                         $app_pki_cert          = $simp_openldap::app_pki_cert,
  Stdlib::Absolutepath                         $app_pki_key           = $simp_openldap::app_pki_key,
  Optional[Stdlib::Absolutepath]               $app_pki_crl           = $simp_openldap::app_pki_crl,
  Optional[Boolean]                            $strip_128_bit_ciphers = undef,
  Array[String[1]]                             $tls_cipher_suite      = simplib::lookup('simp_options::openssl::cipher_suite', { 'default_value' => ['DEFAULT','!MEDIUM'] }),
  Enum['none','peer','all']                    $tls_crlcheck          = 'none',
  Enum['never','searching','finding','always'] $deref                 = 'never',
  Enum['never','allow','try','demand','hard']  $tls_reqcert           = 'allow',
  String                                       $openldap_clients_ensure = simplib::lookup('simp_options::package_ensure', { 'default_value' => 'installed' }),
  String                                       $nss_pam_ldapd_ensure    = simplib::lookup('simp_options::package_ensure', { 'default_value' => 'installed' }),
) inherits simp_openldap {

  file { '/etc/openldap/ldap.conf':
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => template("${module_name}/etc/openldap/ldap.conf.erb")
  }

  # Set up root's ldaprc file
  file { '/root/.ldaprc':
    owner   => 'root',
    group   => 'root',
    mode    => '0600',
    replace => false,
    content => template("${module_name}/ldaprc.erb")
  }

  package { "openldap-clients.${facts['os']['hardware']}":
    ensure => $openldap_clients_ensure
  }
}
