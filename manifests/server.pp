#
# == Class: openldap::server
#
# This class sets up an OpenLDAP server.
#
# It installs the server if not already installed and bootstraps it if
# necessary.
#
# You can quickly reset the entire server by removing all files from
# /var/lib/ldap/db/* and then re-runing puppet. Note that this will
# erase the contents of your database, so you will want to use slapcat
# to save any data that you may require later for restoration.
#
# If you need to re-bootstrap, you also must remove the file
# '/etc/openldap/puppet_bootstrapped.lock' since this is in place as a
# protective measure.
#
# Please look at the openldap::server::access::add stanzas below so
# that you can understand how to modify the access controls via
# puppet.
#
# The default access settings start at 1000 and go through 3000 except
# for a default entry at 100000 that allows users to read everything
# and then denies access. These are spread this far apart so that you
# can easily override and/or circumvent them to your site
# specifications.
#
# NOTE: To get the bootstrap to run again, you must remove the lock
# file at /etc/openldap/puppet_bootstrapped.lock *and* remove the
# database files in /var/lib/ldap/db/*.
#
# == Parameters:
#
# [*schema_sync*]
# Type: Boolean
# Default: true
#   Synchronize all schemas from $schema_source.
#
# [*schema_source*]
# Type: URI
# Default: puppet:///modules/openldap/etc/openldap/schema
#   The location from which to download the schemas.
#
# [*allow_sync*]
# Type: Boolean
# Default: true
#   If true, provide the ability for other hosts to use LDAP
#   synchronization as clients to this server.
#
#   Class variables will need to be set in hiera according to the
#   openldap::slapo::syncprov class requirements.
#
# [*sync_dn*]
# Type: LDAP DN
# Default: hiera('ldap::sync_dn',"LDAPSync,ou=People,${::openldap::base_dn}")
#   The DN that is allowed to synchronize from the LDAP server.
#
# [*host_auth_user*]
# Type: String
# Default: hostAuth
#   The LDAP username that will be used by the various hosts to bind
#   to the LDAP server.
#
# [*use_ppolicy*]
# Type: Boolean
# Default: true
#   If true, include the default password policy overlay.
#
# [*use_tcpwrappers*]
# Type: Boolean
# Default: true
#   If true, enable tcpwrappers for slapd.
#
# == Authors:
#
#   * Trevor Vaughan <tvaughan@onyxpoint.com>
#
class openldap::server (
  $schema_sync = true,
  $schema_source = 'puppet:///modules/openldap/etc/openldap/schema',
  $allow_sync = true,
  $sync_dn = hiera('ldap::sync_dn',"cn=LDAPSync,ou=Hosts,${::openldap::base_dn}"),
  $host_auth_user = 'hostAuth',
  $use_ppolicy = true,
  $use_tcpwrappers = true
) inherits ::openldap {

  validate_bool($schema_sync)
  validate_bool($allow_sync)
  validate_bool($use_ppolicy)
  validate_bool($use_tcpwrappers)

  compliance_map()

  include '::openldap::client'
  include '::openldap::server::access'
  include '::openldap::server::dynamic_includes'
  include '::openldap::server::service'

  if $allow_sync {
    include '::openldap::slapo::syncprov'
  }

  if $use_ppolicy {
    include '::openldap::slapo::ppolicy'
  }

  # This needs to come after ppolicy and syncprov since some templates
  # use the values.
  include '::openldap::server::conf'

  file { '/etc/openldap':
      owner   => 'root',
      group   => 'ldap',
      recurse => true,
      require => Package["openldap-servers.${::hardwaremodel}"]
  }

  file { '/var/lib/ldap/DB_CONFIG':
      ensure  => 'symlink',
      target  => '/etc/openldap/DB_CONFIG',
      require => Package["openldap-servers.${::hardwaremodel}"]
  }

  if $schema_sync {
    file { '/etc/openldap/schema':
      owner   => 'root',
      group   => 'ldap',
      mode    => '0644',
      recurse => true,
      source  => $schema_source,
      require => Package["openldap-servers.${::hardwaremodel}"]
    }
  }
  else {
    file { '/etc/openldap/schema':
      owner   => 'root',
      group   => 'ldap',
      mode    => '0644',
      recurse => true,
      require => Package["openldap-servers.${::hardwaremodel}"]
    }
  }

  file { [ '/var/lib/ldap', '/var/lib/ldap/db', '/var/lib/ldap/logs' ]:
      ensure  => 'directory',
      owner   => 'ldap',
      group   => 'ldap',
      mode    => '0660',
      require => Package["openldap-servers.${::hardwaremodel}"]

  }

  file { '/var/log/slapd.log':
      owner   => 'root',
      group   => 'root',
      mode    => '0600',
      require => Package["openldap-servers.${::hardwaremodel}"]
  }

  file { '/etc/openldap/dynamic_includes':
      ensure    => 'file',
      owner     => 'root',
      group     => 'ldap',
      mode      => '0640',
      require   => Package["openldap-servers.${::hardwaremodel}"],
      subscribe => Simpcat_build['slapd_dynamic_includes'],
      notify    => Class['openldap::server::service'],
      audit     => content
  }

  file { '/usr/local/sbin/ldap_bootstrap_check.sh':
    ensure  => 'file',
    owner   => 'root',
    group   => 'root',
    mode    => '0750',
    source  => 'puppet:///modules/openldap/usr/local/sbin/ldap_bootstrap_check.sh',
    require => [
      File['/var/lib/ldap/DB_CONFIG'],
      File['/var/lib/ldap/db'],
      File['/var/lib/ldap/logs'],
      File['/etc/openldap/slapd.conf'],
      File['/etc/openldap/slapd.access'],
      File['/etc/openldap/default.ldif'],
      File['/etc/openldap/dynamic_includes'],
      File['/etc/openldap/schema']
    ]
  }

  group { 'ldap':
    ensure    => 'present',
    allowdupe => false,
    gid       => '55',
    require   => Package["openldap-servers.${::hardwaremodel}"]
  }

  # This adds the default entries to LDAP in a wide spacing for other users
  # to usefully add their own materials.
  openldap::server::access::add { 'simp_userpassword_access':
    what    =>  'attrs=userPassword',
    content => "
      by dn.exact=\"${sync_dn}\" read
      by dn.exact=\"${::openldap::bind_dn}\" auth
      by anonymous auth
      by self write
      by * none
    ",
    order   => '1000'
  }

  # Yes, we know that allowing 'self' to write shadowLastChange is a
  # potential security issue. However, if you leave the default
  # password policy in place then this is completely mitigated and,
  # if you find a discrepancy, someone was trying to do bad things
  # on your system.
  openldap::server::access::add { 'simp_shadowlastchange_access':
    what    => 'attrs=shadowLastChange',
    content => "
      by dn.exact=\"${sync_dn}\" read
      by dn.exact=\"${::openldap::bind_dn}\" read
      by anonymous auth
      by self write
      by * none
    ",
    order   => '2000'
  }

  openldap::server::access::add { 'simp_loginshell_access':
    what    => 'attrs=loginShell',
    content => "
      by self write
      by * read
      by * none
    ",
    order   => '3000'
  }

  # The following two items really need to be last and act as an example of
  # calling out items that work on the same 'what' option.
  openldap::server::access::add { 'simp_default_user_access':
    what   => '*',
    who    => 'users',
    access => 'read',
    order  => '100000'
  }

  openldap::server::access::add { 'simp_default_user_reject':
    what   => '*',
    who    => '*',
    access => 'none',
    order  => '100001'
  }

  # Add a user that is allowed to authenticate to bind to the system
  # for host use. Make sure that all entries are available to that
  # user.
  openldap::server::add_limits { $host_auth_user:
    who    => $::openldap::bind_dn,
    limits => [
      'size.soft=unlimited',
      'size.hard=unlimited',
      'size.prtotal=unlimited'
    ]
  }

  package { 'openldap': ensure => 'latest' }
  package { "openldap-servers.${::hardwaremodel}": ensure => 'latest' }

  if $use_tcpwrappers {
    include '::tcpwrappers'

    tcpwrappers::allow { 'slapd':
      pattern => 'ALL',
      order   => '1'
    }
  }

  user { 'ldap':
    ensure     => 'present',
    allowdupe  => false,
    uid        => '55',
    gid        => '55',
    home       => '/var/lib/ldap',
    membership => 'inclusive',
    shell      => '/sbin/nologin',
    require    => Package["openldap-servers.${::hardwaremodel}"],
    notify     => Class['openldap::server::service']
  }
}
