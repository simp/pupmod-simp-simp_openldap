# == Class: openldap::server::conf
#
# This class configures the brunt of the /etc/openldap space.
#
# It should only be included by the openldap::server class and is not
# meant to be used alone.
#
# Regarding: POODLE - CVE-2014-3566
#
# The tls_cipher_suite variable is set to HIGH:-SSLv2 because OpenLDAP
# cannot set the SSL provider natively. By default, it will run TLSv1
# but cannot handle TLSv1.2 therefore the SSLv3 ciphers cannot be
# eliminated. Take care to ensure that your clients only connect with
# TLSv1 if possible.
#
# == Parameters
#
# See slapd.conf(5) and slapd-bdb(5) for any variable that is not
# explicitly defined below.
#
# [*rootdn*]
# Type: LDAP DN
# Default: hiera('ldap::root_dn',"LDAPAdmin,ou=People,${::openldap::base_dn}")
#   The username of the administrative LDAP user
#
# [*rootpw*]
# Type: 'slappasswd' generated hash
# Default: hiera('ldap::root_hash')
#   This is the output of 'slappasswd' for your LDAP root account.
#
# [*syncdn*]
# Type: LDAP DN
# Default: hiera('ldap::sync_dn',"LDAPSync,ou=People,${::openldap::base_dn}")
#   The username of the LDAP synchronization user. Used for DB replication.
#
# [*syncpw*]
# Type: 'slappasswd' generated hash
# Default: hiera('ldap::sync_hash')
#   This is the output of 'slappasswd' for your LDAP sync account.
#
# [*binddn*]
# Type: LDAP DN
# Default: hiera('ldap::bind_dn',"hostAuth,ou=Hosts,${::openldap::base_dn}")
#   The username of the LDAP host authorization user. This user should not have
#   the ability to do anything besides bind to the LDAP system for further
#   authentication.
#
# [*bindpw*]
# Type: 'slappasswd' generated hash
# Default: hiera('ldap::bind_hash')
#   This is the output of 'slappasswd' for your LDAP bind account.
#
# [*audit_transactions*]
# Type: Boolean
# Default: true
#   If true, will cause OpenLDAP to audit all transactions in the
#   database. This will output an LDIF file with all details of what
#   changed on the system and may contain sensitive information.
#
# [*audit_to_syslog*]
# Type: Boolean
# Default: true
#   If true, will forward all audit logs to syslog. Like above, this
#   will forward all information to syslog and may contain sensitive
#   information.
#
# [*auditlog*]
# Type: Absolute Path
# Default: '/var/log/slapd.audit'
#   The path to the slapd audit log. Only effective if
#   audit_transactions is true.
#
# [*auditlog_rotate*]
# Type: One of daily, weekly, monthly, or yearly
# Default: 'daily'
#   The frequency with which the slapd audit logs should be rotated.
#
# [*auditlog_preserve*]
# Type: Integer
# Default: '7'
#   The number of rotated audit logs to preserve.
#
# [*authz_policy*]
# Type: String
# Default: 'to'
#   Set the appropriate authz-policy entry.
#   May be one of 'none', 'from', 'to', or 'any'
#
# [*authz_regexp*]
# Type: Array of Hashes
# Default:
#   [{
#     'match'   => '^uid=([^,]+),.*',
#     'replace' => "uid=\$1,ou=People,${::basedn}"
#   }]
#
#   Used to convert simple usernames to an LDAP DN for authorization.
#   Set to an empty array '[]' to have this value ignored.
#
#   Entries will be added to the configuration file in order so order
#   them from most strict to least strict.
#
#   Note: The default is fairly lenient and you may want to tighten
#   this up.
#
# [*default_schemas*]
# Type: Array of Strings
# Default:
#   [
#     'openssh-lpk',
#     'freeradius',
#     'autofs'
#   ]
#
#   The default schemas from /etc/openldap/schema to include.
#   /etc/openldap/schema will be prepended and '.schema' will be
#   appended. It is highly recommended that you keep this list if you
#   decide to override, however, these defaults will *not* be merged
#   with what you provide.
#
#   Core, Cosine, InetOrgPerson, and NIS will always be included.
#
# [*client_nets*]
# Type: Array of Networks
# Default: hiera('client_nets')
#   The networks that should be allowed into the server.
#
# [*force_log_quick_kill*]
# Type: Boolean
# Default: false
#   If true, create an incron job that will *immediately* destroy any
#   recovery log file written to the log directory. Setting this to
#   'true' is not recommended but can be used on systems where you
#   have issues with recovery log size and the way that OpenLDAP
#   manages them.
#
# [*include_chain_overlay*]
# Type: Boolean
# Default: true
#   If true, includes a chain overlay to allow for referral chaining.
#   This is only needed on slave nodes.
#
# [*listen_ldap*]
# Type: Boolean
# Default: true
#   If true, listen on the default LDAP port for ldap:// conenctions.
#
# [*listen_ldapi*]
# Type: Boolean
# Default: false
#   If true, listen on the default LDAP port for ldapi:// conenctions.
#
# [*listen_ldaps*]
# Type: Boolean
# Default: true
#   If true, listen on the default LDAPS port for ldaps:// conenctions.
#
# [*custom_options*]
# Type: Array
# Default: []
#   An array of command line options that will be placed into the openldap
#   configuration file. These are in no way validated for correct
#   functionality!
#
# [*password_hash*]
# Type: One of 'SSHA', 'SHA', 'SMD5', 'MD5', 'CRYPT', or 'CLEARTEXT'
# Default: SSHA
#   The hash algorithm to use for
#
# [*sizelimit*]
# Type: Integer
# Default: 500
#   The default size limit for queries.
#   If any of the $sizelimit_* options are set, this will be
#   overridden in slapd.conf.
#
# [*sizelimit_soft*]
# Type: Integer
# Default: 500
#   Corresponds to size.soft in slapd.conf.
#
# [*sizelimit_hard*]
# Type: Integer
# Default: 500
#   Corresponds to size.hard in slapd.conf.
#
# [*sizelimit_unchecked*]
# Type: Integer
# Default: 500
#   Corresponds to size.unchecked in slapd.conf.
#
# [*slapd_shutdown_timeout*]
# Type: Integer
# Default: 3
#   Maximum allowed time to wait for slapd shutdown on 'service ldap
#   stop' (in seconds).
#
# [*threads*]
# Type: Integer or 'dynamic'
# Default: 'dynamic'
#   Set the number of threads to run. If not set to a number, will be assumed to
#   be dynamic with 4 * the number of cpus. It also has a minimum of 8 and a max
#   of 16, unless overridden.
#
# [*timelimit*]
# Type: Integer
# Default: 3600
#   The default time limit for queries.
#   If any of the $timelimit_* options are set, this will be
#   overridden in slapd.conf.
#
# [*timelimit_soft*]
# Type: Integer
# Default: 3600
#   Corresponds to time.soft in slapd.conf.
#
# [*timelimit_hard*]
# Type: Integer
# Default: 3600
#   Corresponds to time.hard in slapd.conf.
#
# [*use_tls*]
# Type: Boolean
# Default: true
#   If true, enable TLS.
#
# [*tlsVerifyClient*]
# Type: One of 'never', 'allow', 'try', 'demand', 'hard', or 'true'
# Default: 'try'
#   Do not set this more restrictive than 'try' unless you *really*
#   know what you are doing and have exensively tested it in your
#   environment!
#
# [*db_cachesize*]
# Type: \d+ \d+ \d+
# Default: '0 268435456 1'
#   Set the BDB backend cache size. The format is <gigabytes> <bytes>
#   <segements>.
#
# [*db_log_autoremove*]
# Type: Boolean
# Default: true
#   This tells the OpenLDAP BDB back end database to automatically
#   remove all recovery log files when possible.  Setting this to
#   'true' (the default) means that you are responsible for backing up
#   your database and that incremental recovery may not be possible!
#
# [*ulimit_max_open_files*]
# Type: Integer
# Default: 81920
#   OpenLDAP requires a great number of open file handles. Set this to
#   something reasonable for your system. The default should suffice
#   in most cases.
#
# [*enable_logging*]
# Type: Boolean
# Default: false
#   If true, send the output of local4 to /var/log/ldap.log.
#
# [*log_file*]
# Type: Absolute Path
# Default: '/var/log/slapd.log'
#   If $enable_logging is true, output all logs to this file via
#   syslog.
#
# [*use_iptables*]
# Type: Boolean
# Default: true
#   If true, enable the SIMP iptables for OpenLDAP.
#
# == Authors
#
#   * Trevor Vaughan <tvaughan@onyxpoint.com>
#
class openldap::server::conf (
  $rootdn = hiera('ldap::root_dn',"LDAPAdmin,ou=People,${::openldap::base_dn}"),
  $rootpw = hiera('ldap::root_hash'),
  $syncdn = hiera('ldap::sync_dn',"LDAPSync,ou=People,${::openldap::base_dn}"),
  $syncpw = hiera('ldap::sync_hash'),
  $binddn = hiera('ldap::bind_dn',"hostAuth,ou=Hosts,${::openldap::base_dn}"),
  $bindpw = hiera('ldap::bind_hash'),
  $suffix = $::openldap::base_dn,
  $argsfile = '/var/run/openldap/slapd.args',
  $audit_transactions = true,
  $audit_to_syslog = true,
  $auditlog = '/var/log/slapd.audit',
  $auditlog_rotate = 'daily',
  $auditlog_preserve = '7',
  $authz_policy = 'to',
  $authz_regexp = [{
    'match'   => '^uid=([^,]+),.*',
    'replace' => "uid=\$1,ou=People,${::openldap::base_dn}"
  }],
  $bind_anon = false,
  $cachesize = '10000',
  $checkpoint = '1024 5',
  $client_nets = hiera('client_nets'),
  $concurrency = '',
  $conn_max_pending = '100',
  $conn_max_pending_auth = '100',
  $default_schemas = [
    'openssh-lpk',
    'freeradius',
    'autofs'
  ],
  $default_searchbase = '',
  $disallow = ['bind_anon','tls_2_anon'],
  $force_log_quick_kill = false,
  $ditcontentrule = '',
  $gentlehup = false,
  $idletimeout = '0',
  $include_chain_overlay = false,
  $index_substr_any_step = '2',
  $index_substr_any_len = '4',
  $index_substr_if_maxlen = '4',
  $index_substr_if_minlen = '2',
  $index_intlen = '4',
  $listen_ldap = true,
  $listen_ldapi = true,
  $listen_ldaps = true,
  $custom_options = [],
  $slapd_logLevel = ['stats', 'acl', 'sync'],
  $password_crypt_salt_format = '%s',
  $password_hash = 'SSHA',
  $pidfile = '/var/run/openldap/slapd.pid',
  $reverse_lookup = false,
  $schemadn = 'cn=Subschema',
  $security = 'ssf=256 tls=256 update_ssf=256 simple_bind=256 update_tls=256',
  $sizelimit = '500',
  $sizelimit_soft = '500',
  $sizelimit_hard = '500',
  $sizelimit_unchecked = '500',
  $slapd_shutdown_timeout = '3',
  $sockbuf_max_incoming = '262143',
  $sockbuf_max_incoming_auth = '4194303',
  $sortvals = [],
  $tcp_buffer = '',
  $threads = 'dynamic',
  $timelimit = '3600',
  $timelimit_soft = '3600',
  $timelimit_hard = '3600',
  $writetimeout = '0',
  $use_tls = true,
  $tlsCACertificatePath = '/etc/openldap/pki/cacerts',
  $tlsCertificateFile = "/etc/openldap/pki/public/${::fqdn}.pub",
  $tlsCertificateKeyFile = "/etc/openldap/pki/private/${::fqdn}.pem",
  $tlsCipherSuite = 'DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-DSS-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA256:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:AECDH-AES256-SHA:ADH-AES256-GCM-SHA384:ADH-AES256-SHA256:ADH-AES256-SHA:ECDH-RSA-AES256-GCM-SHA384:ECDH-ECDSA-AES256-GCM-SHA384:ECDH-RSA-AES256-SHA384:ECDH-ECDSA-AES256-SHA384:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:AES256-GCM-SHA384:AES256-SHA256:AES256-SHA',
  $tlsCRLCheck = 'none',
  $tlsCRLFile = '',
  $tlsVerifyClient = 'try',
  $database = 'bdb',
  $directory = '/var/lib/ldap',
  $db_add_content_acl = false,
  $db_lastmod = true,
  $db_maxderefdepth = '15',
  $db_mirrormode = false,
  $db_monitoring = true,
  $db_readonly = false,
  $db_cachesize = '0 268435456 1',
  $db_max_locks = '3000',
  $db_max_lock_objects = '1500',
  $db_max_lock_lockers = '1500',
  $db_log_region_max_size = '262144',
  $db_log_buffer_size = '2097152',
  $db_log_autoremove = true,
  $ulimit_max_open_files = '81920',
  $enable_logging = false,
  $log_file = '/var/log/slapd.log',
  $use_iptables = true
) {
  include 'openldap::server'

  if $use_tls {
    pki::copy { '/etc/openldap':
      group  => 'ldap',
      notify => Service[$openldap::server::slapd_svc]
    }
  }

  if $::hardwaremodel == 'x86_64' {
      $modulepath = ['/usr/lib64/openldap','/usr/lib/openldap']
  }
  else {
      $modulepath = ['/usr/lib/openldap']
  }

  if $force_log_quick_kill {
    include 'common::incron'

    common::incron::add_system_table { 'nuke_openldap_log_files':
      path    => "${directory}/logs",
      mask    => ['IN_CREATE'],
      command => '/bin/rm $@/$#'
    }
  }

  file { $modulepath:
    owner   => 'root',
    group   => 'root',
    mode    => '0755',
    recurse => true
  }

  file { '/etc/openldap/slapd.conf':
    ensure  => 'file',
    owner   => 'root',
    group   => 'ldap',
    mode    => '0640',
    content => template('openldap/etc/openldap/slapd.conf.erb'),
    notify  => Service[$openldap::server::slapd_svc]
  }

  file { '/etc/openldap/DB_CONFIG':
    ensure  => 'file',
    owner   => 'root',
    group   => 'ldap',
    mode    => '0640',
    content => template('openldap/etc/openldap/DB_CONFIG.erb'),
    notify  => Service[$openldap::server::slapd_svc]
  }

  $_simp_ppolicy_check_password = $::openldap::slapo::ppolicy::check_password
  file { '/etc/openldap/default.ldif':
    ensure  => 'file',
    owner   => 'root',
    group   => 'ldap',
    mode    => '0640',
    content => template('openldap/etc/openldap/default.ldif.erb'),
  }

  if ($::operatingsystem in ['RedHat','CentOS']) and ($::operatingsystemmajrelease > '6') {
    file { '/etc/sysconfig/slapd':
      ensure  => 'file',
      owner   => 'root',
      group   => 'root',
      mode    => '0640',
      content => template('openldap/etc/sysconfig/slapd.erb'),
      notify  => Service[$::openldap::server::slapd_svc]
    }
  }
  else {
    file { '/etc/sysconfig/ldap':
      ensure  => 'file',
      owner   => 'root',
      group   => 'root',
      mode    => '0640',
      content => template('openldap/etc/sysconfig/ldap.erb'),
      notify  => Service[$::openldap::server::slapd_svc]
    }
  }

  # IPTables
  if $use_iptables {
    include 'iptables'
    if $listen_ldap or $listen_ldaps {
      iptables::add_tcp_stateful_listen { 'allow_ldap':
        order       => '11',
        client_nets => $client_nets,
        dports      => 'ldap'
      }
    }
    if $listen_ldaps {
      iptables::add_tcp_stateful_listen { 'allow_ldaps':
        order       => '11',
        client_nets => $client_nets,
        dports      => 'ldaps'
      }
    }
  }

  if $audit_transactions {
    file { $auditlog:
      ensure => 'present',
      owner  => 'ldap',
      group  => 'ldap',
      mode   => '0750'
    }

    include 'logrotate'

    logrotate::add { 'slapd_audit_log':
      log_files     => $auditlog,
      create        => '0640 ldap ldap',
      rotate_period => $auditlog_rotate,
      rotate        => $auditlog_preserve
    }

    openldap::server::dynamic_includes::add { 'auditlog':
      order   => '1000',
      content => template('openldap/slapo/auditlog.erb'),
      require => File[$auditlog]
    }

    if $audit_to_syslog {
      include 'rsyslog'
      rsyslog::rule::other { 'openldap_audit':
        rule    => "
input(type=\"imfile\"
  File=\"${auditlog}\"
  StateFile=\"openldap_audt\"
  Tag=\"slapd_audit\"
  Facility=\"local6\"
  Severity=\"notice\"
)",
        require => File[$auditlog]
      }

      rsyslog::rule::drop { '1_openldap_drop_passwords':
        rule => '
# Drop passwords from OpenLDAP audit logs.
if $syslogfacility-text == \'local6\' and $msg contains \'Password:: \''
      }
    }
  }

  if $enable_logging {
    include 'logrotate'
    include 'rsyslog'

    rsyslog::rule::local { 'openldap':
      rule            => "local4.*",
      target_log_file => "/var/log/${log_file}"
    }

    logrotate::add { 'slapd':
      log_files  => [ $log_file ],
      missingok  => true,
      lastaction => '/sbin/service rsyslog restart > /dev/null 2>&1 || true'
    }
  }

  validate_absolute_path($argsfile)
  validate_bool($audit_transactions)
  validate_bool($audit_to_syslog)
  validate_absolute_path($auditlog)
  validate_integer($auditlog_preserve)
  validate_array_member($authz_policy,['none','from','to','any'])
  validate_array_of_hashes($authz_regexp)
  validate_bool($bind_anon)
  validate_integer($cachesize)
  validate_re($checkpoint,'^\d+\s\d+$')
  validate_net_list($client_nets)
  validate_integer($conn_max_pending)
  validate_integer($conn_max_pending_auth)
  validate_array($default_schemas)
  validate_array($disallow)
  validate_bool($force_log_quick_kill)
  validate_bool($gentlehup)
  validate_integer($idletimeout)
  validate_bool($include_chain_overlay)
  validate_integer($index_substr_any_step)
  validate_integer($index_substr_any_len)
  validate_integer($index_substr_if_maxlen)
  validate_integer($index_substr_if_minlen)
  validate_integer($index_intlen)
  validate_bool($listen_ldap)
  validate_bool($listen_ldapi)
  validate_bool($listen_ldaps)
  validate_array($custom_options)
  validate_array($slapd_logLevel)
  validate_array_member($password_hash,['SSHA','SHA','SMD5','MD5','CRYPT','CLEARTEXT'])
  # Cast threads to a string so it can be regex against both
  # digits and the string 'dynamic'
  validate_re("${threads}",'^(\d+|dynamic)$')
  validate_absolute_path($pidfile)
  validate_bool($reverse_lookup)
  validate_re($sizelimit,'^(\d+|unlimited)$')
  validate_re($sizelimit_soft,'^(\d+|unlimited)$')
  validate_re($sizelimit_hard,'^(\d+|unlimited)$')
  validate_re($sizelimit_unchecked,'^(\d+|unlimited)$')
  validate_integer($slapd_shutdown_timeout)
  validate_integer($sockbuf_max_incoming)
  validate_integer($sockbuf_max_incoming_auth)
  validate_array($sortvals)
  if ! empty($tcp_buffer) { validate_integer($tcp_buffer) }
  validate_re($timelimit,'^(\d+|unlimited)$')
  validate_re($timelimit_soft,'^(\d+|unlimited)$')
  validate_re($timelimit_hard,'^(\d+|unlimited)$')
  validate_integer($writetimeout)
  validate_absolute_path($tlsCACertificatePath)
  validate_absolute_path($tlsCertificateFile)
  validate_absolute_path($tlsCertificateKeyFile)
  if !empty($tlsCRLFile) {  validate_absolute_path($tlsCRLFile) }
  validate_array_member($tlsCRLCheck,['none','peer','all'])
  validate_array_member($tlsVerifyClient,['never','allow','try','demand','hard',true])
  validate_array_member($database,[
    'bdb',
    'config',
    'dnssrv',
    'hdb',
    'ldap',
    'ldif',
    'meta',
    'monitor',
    'null',
    'passwd',
    'perl',
    'relay',
    'shell',
    'sql']
  )
  validate_absolute_path($directory)
  validate_bool($db_add_content_acl)
  validate_bool($db_lastmod)
  validate_integer($db_maxderefdepth)
  validate_bool($db_mirrormode)
  validate_bool($db_monitoring)
  validate_bool($db_readonly)
  validate_re($db_cachesize,'^\d+ \d+ \d+$')
  validate_integer($db_max_locks)
  validate_integer($db_max_lock_objects)
  validate_integer($db_max_lock_lockers)
  validate_integer($db_log_region_max_size)
  validate_integer($db_log_buffer_size)
  validate_bool($db_log_autoremove)
  validate_integer($ulimit_max_open_files)
  validate_bool($enable_logging)
  validate_absolute_path($log_file)
  validate_bool($use_tls)
  validate_bool($use_iptables)
}
