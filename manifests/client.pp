# == Class: openldap::client
#
# Set up /etc/openldap/ldap.conf with the global options for accessing the LDAP
# servers.
#
# See ldap.conf(5) for details.
#
# Regarding: POODLE - CVE-2014-3566
#
# The tls_cipher_suite variable is set to HIGH:-SSLv2 because OpenLDAP
# cannot set the SSL provider natively. By default, it will run TLSv1
# but cannot handle TLSv1.2 therefore the SSLv3 ciphers cannot be
# eliminated. Take care to ensure that your clients only connect with
# TLSv1 if possible.
#
class openldap::client (
    $uri = simplib::lookup('simp_options::ldap::uri', { 'default_value' => ["ldap://${hiera('simp_options::puppet::server')}"], 'value_type' => Array[String] } ),
    $base_dn = simplib::lookup('simp_options::ldap::base_dn', { 'default_value' => undef , 'value_type' => Optional[String] }),
    $bind_dn = simplib::lookup('simp_options::ldap::bind_dn', { 'default_value' => "cn=hostAuth,ou=Hosts,${hiera('simp_options::ldap::base_dn')}", 'value_type' => String }),
    $referrals = 'on',
    $sizelimit = '0',
    $timelimit = '15',
    $deref = 'never',
    $use_tls = simplib::lookup('simp_options::pki', { 'default_value' => false, 'value_type' => Boolean }),
    $app_pki_ca_dir = '/etc/pki/cacerts',
    $app_pki_cert = "/etc/pki/public/${::fqdn}.pub",
    $app_pki_key = "/etc/pki/private/${::fqdn}.pem",
    $tls_cipher_suite = simplib::lookup('simp_options::openssl::cipher_suite', { 'default_value' => ['DEFAULT', '!MEDIUM'], 'value_type' => Array[String] }),
    $tls_reqcert = 'allow',
    $tls_crlcheck = 'none',
    $tls_crlfile = ''
) {
  include '::openldap'

  file { '/etc/openldap/ldap.conf':
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => template('openldap/etc/openldap/ldap.conf.erb')
  }

  # Set up root's ldaprc file.
  file { '/root/.ldaprc':
    owner   => 'root',
    group   => 'root',
    mode    => '0600',
    replace => false,
    content => template('openldap/ldaprc.erb')
  }

  package { "openldap-clients.${::hardwaremodel}": ensure => 'latest' }
  package { 'nss-pam-ldapd':                       ensure => 'latest' }


  validate_array_member($referrals,['on','off'])
  validate_integer($sizelimit)
  validate_integer($timelimit)
  validate_array_member($deref,['never','searching','finding','always'])
  validate_absolute_path($app_pki_ca_dir)
  validate_absolute_path($app_pki_cert)
  validate_absolute_path($app_pki_key)
  validate_array($tls_cipher_suite)
  validate_array_member($tls_reqcert,['never','allow','try','demand','hard'])
  validate_array_member($tls_crlcheck,['none','peer','all'])
  if ! empty($tls_crlfile) { validate_absolute_path($tls_crlfile) }

}
