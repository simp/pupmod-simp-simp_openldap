# Set up /etc/openldap/ldap.conf with the global options for accessing the LDAP
# servers.
#
# @see ldap.conf(5) for details.
#
# Regarding: POODLE - CVE-2014-3566
#
# The ``tls_cipher_suite`` parameter is set to ``HIGH:-SSLv2`` because OpenLDAP
# cannot set the SSL provider natively.
#
# By default, it will run TLSv1 but cannot handle TLSv1.2 therefore the SSLv3
# ciphers cannot be eliminated. Take care to ensure that your clients only
# connect with TLSv1 if possible.
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
#   On EL6 systems, all 128-bit ciphers will be removed from ``tls_cipher_suite``
#
#   * This is due to a bug in the LDAP client libraries that does not appear to
#     honor the order of the SSL ciphers and will attempt to connect with
#     128-bit ciphers and not use stronger ciphers when those are present. This
#     breaks connections to securely configured LDAP servers.
#
# @param openldap_clients_ensure The ensure status of the openldap-clients package
# @param nss_pam_ldapd_ensure The ensure status of the nss-pam-ldapd package
#
class simp_openldap::client (
  Array[Simplib::URI]                          $uri                   = $::simp_openldap::_ldap_uri,
  Optional[String]                             $base_dn               = $::simp_openldap::base_dn,
  String[1]                                    $bind_dn               = $::simp_openldap::bind_dn,
  Enum['on','off']                             $referrals             = 'on',
  Integer                                      $sizelimit             = 0,
  Integer                                      $timelimit             = 15,
  Variant[Enum['simp'],Boolean]                $use_tls               = $::simp_openldap::pki,
  Stdlib::Absolutepath                         $app_pki_ca_dir        = $::simp_openldap::app_pki_ca_dir,
  Stdlib::Absolutepath                         $app_pki_cert          = $::simp_openldap::app_pki_cert,
  Stdlib::Absolutepath                         $app_pki_key           = $::simp_openldap::app_pki_key,
  Optional[Stdlib::Absolutepath]               $app_pki_crl           = $::simp_openldap::app_pki_crl,
  Boolean                                      $strip_128_bit_ciphers = true,
  Array[String[1]]                             $tls_cipher_suite      = simplib::lookup('simp_options::openssl::cipher_suite', { 'default_value' => ['DEFAULT','!MEDIUM'] }),
  Enum['none','peer','all']                    $tls_crlcheck          = 'none',
  Enum['never','searching','finding','always'] $deref                 = 'never',
  Enum['never','allow','try','demand','hard']  $tls_reqcert           = 'allow',
  String                                       $openldap_clients_ensure = simplib::lookup('simp_options::package_ensure', { 'default_value' => 'installed' }),
  String                                       $nss_pam_ldapd_ensure    = simplib::lookup('simp_options::package_ensure', { 'default_value' => 'installed' }),
) inherits ::simp_openldap {

  if $strip_128_bit_ciphers {
    # This is here due to a bug in the LDAP client library on EL6 that will set
    # the SSF to 128 when connecting over StartTLS if there are *any* 128-bit
    # ciphers in the list.
    if versioncmp($facts['os']['release']['major'],'7') < 0 {
      $_tmp_suite = flatten($tls_cipher_suite.map |$cipher| { split($cipher,':') })
      $_tls_cipher_suite = $_tmp_suite.filter |$cipher| { $cipher !~ Pattern[/128/] }
    }
    else {
      $_tls_cipher_suite = $tls_cipher_suite
    }
  }
  else {
    $_tls_cipher_suite = $tls_cipher_suite
  }

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

  package { "openldap-clients.${facts['hardwaremodel']}":
    ensure => $openldap_clients_ensure
  }
  package { 'nss-pam-ldapd':
    ensure => $nss_pam_ldapd_ensure
  }
}
