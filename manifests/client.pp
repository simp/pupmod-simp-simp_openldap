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
  Array[String]              $uri              = simplib::lookup('simp_options::ldap::uri',
                                                  { 'default_value' => ["ldap://${hiera('simp_options::puppet::server')}"] } ),
  Optional[String]           $base_dn          = simplib::lookup('simp_options::ldap::base_dn', { 'default_value' => undef }),
  String                     $bind_dn          = simplib::lookup('simp_options::ldap::bind_dn',
                                                  { 'default_value' => "cn=hostAuth,ou=Hosts,${hiera('simp_options::ldap::base_dn')}" }),
  Enum['on','off']           $referrals        = 'on',
  Integer                    $sizelimit        = 0,
  Integer                    $timelimit        = 15,
  Boolean                    $pki              = simplib::lookup('simp_options::pki', { 'default_value' => false }),
  Boolean                    $use_simp_pki     = simplib::lookup('simp_options::pki', { 'default_value' => false }),
  Optional[Stdlib::Absolutepath]       $app_pki_dir      = "${::openldap::app_pki_dir}",
  Optional[Stdlib::Absolutepath]       $app_pki_ca_dir   = "${::openldap::app_pki_dir}/pki/cacerts",
  Stdlib::Absolutepath       $app_pki_cert     = "${::openldap::app_pki_dir}/pki/public/${::fqdn}.pub",
  Stdlib::Absolutepath       $app_pki_key      = "${::openldap::app_pki_dir}/pki/private/${::fqdn}.pem",
  Boolean                    $is_server        = $::openldap::is_server,
  Array[String]              $tls_cipher_suite = simplib::lookup('simp_options::openssl::cipher_suite', 
                                                   { 'default_value' => ['DEFAULT', '!MEDIUM'] }),
  Enum['none','peer','all']                        $tls_crlcheck     = 'none',
  Variant[Enum[''],Stdlib::Absolutepath]           $tls_crlfile      = '',
  Enum['never','searching','finding','always']     $deref       = 'never',
  Enum['never','allow','try','demand','hard']      $tls_reqcert = 'allow'
) {
  include '::openldap'

  unless $is_server {
    if $pki and $use_simp_pki {
      file { "${app_pki_dir}" :
        ensure => 'directory',
        owner  => 'root',
        group  => 'root',
        mode   => '0644',
        before => Class['Pki']
      }

      include '::pki'
      pki::copy { "${app_pki_dir}":
      }
    }
  }

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

}
