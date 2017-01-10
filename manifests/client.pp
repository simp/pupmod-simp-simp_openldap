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
#   Use TLS when connecting to the ldap server
#
class openldap::client (
  Array[Simplib::URI]                          $uri                 = $::openldap::_ldap_uri,
  Optional[String]                             $base_dn             = $::openldap::base_dn,
  String[1]                                    $bind_dn             = $::openldap::bind_dn,
  Enum['on','off']                             $referrals           = 'on',
  Integer                                      $sizelimit           = 0,
  Integer                                      $timelimit           = 15,
  Boolean                                      $use_tls             = true,
  Optional[Stdlib::Absolutepath]               $app_pki_ca_dir      = "${::openldap::app_pki_dir}/cacerts",
  Stdlib::Absolutepath                         $app_pki_cert        = "${::openldap::app_pki_dir}/public/${facts['fqdn']}.pub",
  Stdlib::Absolutepath                         $app_pki_key         = "${::openldap::app_pki_dir}/private/${facts['fqdn']}.pem",
  Array[String[1]]                             $tls_cipher_suite    = simplib::lookup('simp_options::openssl::cipher_suite', { 'default_value' => ['DEFAULT','!MEDIUM'] }),
  Enum['none','peer','all']                    $tls_crlcheck        = 'none',
  Optional[Stdlib::Absolutepath]               $tls_crlfile         = undef,
  Enum['never','searching','finding','always'] $deref               = 'never',
  Enum['never','allow','try','demand','hard']  $tls_reqcert         = 'allow'
) inherits ::openldap {

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

  package { "openldap-clients.${facts['hardwaremodel']}": ensure => 'latest' }
  package { 'nss-pam-ldapd': ensure => 'latest' }
}
