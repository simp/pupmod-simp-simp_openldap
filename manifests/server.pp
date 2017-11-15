# Set up an OpenLDAP server
#
# It installs the server if not already installed and bootstraps it if
# necessary.
#
# You can quickly reset the entire server by removing all files from
# ``/var/lib/ldap/db/*`` and then re-runing puppet. Note that this will erase
# the contents of your database, so you will want to use ``slapcat`` to save
# any data that you may require later for restoration.
#
# If you need to re-bootstrap, you also must remove the file
# ``/etc/openldap/puppet_bootstrapped.lock`` since this is in place as a
# protective measure.
#
# Please look at the ``simp_openldap::server::access`` stanzas below so that
# you can understand how to modify the access controls via puppet.
#
# The default access settings start at ``1000`` and go through ``3000`` except
# for a default entry at ``100000`` that allows users to read everything and
# then denies access. These are spread this far apart so that you can easily
# override and/or circumvent them to your site specifications.
#
# **NOTE:** To get the bootstrap to run again, you must remove the lock file at
# ``/etc/openldap/puppet_bootstrapped.lock`` *and* remove the database files in
# ``/var/lib/ldap/db/*``.
#
# @param schema_sync
#   Synchronize all schemas from ``$schema_source``
#
# @param schema_source
#   The location from which to download the schemas
#
# @param allow_sync
#   Provide the ability for other hosts to use LDAP synchronization as clients
#   to this server
#
#   * Class variables will need to be set according to the
#     ``simp_openldap::slapo::syncprov`` class requirements
#
# @param sync_dn
#   The DN that is allowed to synchronize from the LDAP server
#
# @param use_ppolicy
#   Include the default password policy overlay
#
# @param use_tcpwrappers
#   If true, enable tcpwrappers for slapd.
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
#
class simp_openldap::server (
  Boolean $schema_sync   = true,
  String  $schema_source = "puppet:///modules/${module_name}/etc/openldap/schema",
  Boolean $allow_sync    = true,
  String  $sync_dn       = simplib::lookup('simp_options::ldap::sync_dn', { 'default_value' => "cn=LDAPSync,ou=Hosts,${::simp_openldap::base_dn}" }),
  Boolean $use_ppolicy   = true,
  Boolean $tcpwrappers   = simplib::lookup('simp_options::tcpwrappers', { 'default_value' => false })
) inherits ::simp_openldap {

  include '::simp_openldap::client'
  contain '::simp_openldap::server::install'

  if $allow_sync {
    contain '::simp_openldap::slapo::syncprov'

    Class['simp_openldap::server::install'] -> Class['simp_openldap::slapo::syncprov']
  }

  if $use_ppolicy {
    contain '::simp_openldap::slapo::ppolicy'

    Class['simp_openldap::server::install'] -> Class['simp_openldap::slapo::ppolicy']
  }

  # This needs to come after ppolicy and syncprov since some templates
  # use the values.
  contain '::simp_openldap::server::conf'

  Class['simp_openldap::server::install'] ~> Class['simp_openldap::server::service']
  Class['simp_openldap::server::conf'] ~> Class['simp_openldap::server::service']

  file { '/etc/openldap':
    owner   => 'root',
    group   => 'ldap',
    recurse => true,
    require => Class['simp_openldap::server::install']
  }

  file { '/var/lib/ldap/DB_CONFIG':
    ensure  => 'symlink',
    target  => '/etc/openldap/DB_CONFIG',
    require => Class['simp_openldap::server::install']
  }

  if $schema_sync {
    file { '/etc/openldap/schema':
      ensure  => 'directory',
      force   => true,
      owner   => 'root',
      group   => 'ldap',
      mode    => '0644',
      recurse => true,
      source  => $schema_source,
      require => Class['simp_openldap::server::install']
    }
  }
  else {
    file { '/etc/openldap/schema':
      owner   => 'root',
      group   => 'ldap',
      mode    => '0644',
      recurse => true,
      require => Class['simp_openldap::server::install']
    }
  }

  file { [ '/var/lib/ldap', '/var/lib/ldap/db', '/var/lib/ldap/logs' ]:
    ensure  => 'directory',
    owner   => 'ldap',
    group   => 'ldap',
    mode    => '0660',
    require => Class['simp_openldap::server::install']
  }

  file { '/var/log/slapd.log':
    owner   => 'root',
    group   => 'root',
    mode    => '0600',
    require => Class['simp_openldap::server::install']
  }

  file { '/usr/local/sbin/ldap_bootstrap_check.sh':
    ensure  => 'file',
    owner   => 'root',
    group   => 'root',
    mode    => '0750',
    content => file("${module_name}/usr/local/sbin/ldap_bootstrap_check.sh"),
    require => [
      File['/var/lib/ldap/DB_CONFIG'],
      File['/var/lib/ldap/db'],
      File['/var/lib/ldap/logs'],
      File['/etc/openldap/slapd.conf'],
      File['/etc/openldap/default.ldif'],
      File['/etc/openldap/schema']
    ]
  }

  group { 'ldap':
    ensure    => 'present',
    allowdupe => false,
    gid       => 55,
    require   => Class['simp_openldap::server::install']
  }

  user { 'ldap':
    ensure     => 'present',
    allowdupe  => false,
    uid        => 55,
    gid        => 55,
    home       => '/var/lib/ldap',
    membership => 'inclusive',
    shell      => '/sbin/nologin',
    require    => Class['simp_openldap::server::install'],
    notify     => Class['simp_openldap::server::service']
  }

  # This adds the default entries to LDAP in a wide spacing for other users
  # to usefully add their own materials.
  simp_openldap::server::access { 'simp_userpassword_access':
    what    =>  'attrs=userPassword',
    content => "
      by dn.exact=\"${sync_dn}\" read
      by dn.exact=\"${::simp_openldap::bind_dn}\" auth
      by anonymous auth
      by self write
      by * none",
    order   => 1000
  }

  # Yes, we know that allowing 'self' to write shadowLastChange is a
  # potential security issue. However, if you leave the default
  # password policy in place then this is completely mitigated and,
  # if you find a discrepancy, someone was trying to do bad things
  # on your system.
  simp_openldap::server::access { 'simp_shadowlastchange_access':
    what    => 'attrs=shadowLastChange',
    content => "
      by dn.exact=\"${sync_dn}\" read
      by dn.exact=\"${::simp_openldap::bind_dn}\" read
      by anonymous auth
      by self write
      by * none",
    order   => 2000
  }

  simp_openldap::server::access { 'simp_loginshell_access':
    what    => 'attrs=loginShell',
    content => "
      by self write
      by * read
      by * none",
    order   => 3000
  }

  # The following two items really need to be last and act as an example of
  # calling out items that work on the same 'what' option.
  simp_openldap::server::access { 'simp_default_user_access':
    what   => '*',
    who    => 'users',
    access => 'read',
    order  => 100000
  }

  simp_openldap::server::access { 'simp_default_user_reject':
    what   => '*',
    who    => '*',
    access => 'none',
    order  => 100001
  }

  # Add a user that is allowed to authenticate to bind to the system
  # for host use. Make sure that all entries are available to that
  # user.
  simp_openldap::server::limits { 'hostAuth':
    who    => $::simp_openldap::bind_dn,
    limits => [
      'size.soft=unlimited',
      'size.hard=unlimited',
      'size.prtotal=unlimited'
    ]
  }

  if $tcpwrappers {
    include '::tcpwrappers'

    tcpwrappers::allow { 'slapd':
      pattern => 'ALL',
      order   => 1
    }
  }

  contain '::simp_openldap::server::service'

  if $::simp_openldap::pki {
    Pki::Copy['openldap'] ~> Class['simp_openldap::server::service']
  }
}
