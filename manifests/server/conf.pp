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
# [*trusted_nets*]
# Type: Array of Networks
# Default: hiera('trusted_nets')
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
# [*syslog*]
# Type: Boolean
# Default: false
#   If true, enable the SIMP logging infrastructure
#
# [*log_to_file*]
# Type: Boolean
# Default: false
#   If true, send the output logs to the file specified in $log_file.
#   Has no effect if $syslog == false.
#
# [*log_file*]
# Type: Absolute Path
# Default: '/var/log/slapd.log'
#   If $syslog is true, output all logs to this file via
#   syslog.
#   Has no effect if $syslog == false.
#
# [*forward_all_logs*]
# Type: Boolean
# Default: false
#   If true, forward all OpenLDAP logs via rsyslog.
#   Has no effect if $syslog == false.
#
# [*firewall*]
# Type: Boolean
# Default: true
#   If true, enable the SIMP iptables for OpenLDAP.
#
# == Authors
#
#   * Trevor Vaughan <tvaughan@onyxpoint.com>
#
class openldap::server::conf (
  String                $rootdn                     = simplib::lookup('simp_options::ldap::root_dn',
                                                        { 'default_value' => "LDAPAdmin,ou=People,${::openldap::base_dn}" }),
  Optional[String]      $rootpw                     = simplib::lookup('simp_options::ldap::root_hash',{ 'default_value' => undef }),
  String                $syncdn                     = simplib::lookup('simp_options::ldap::sync_dn',
                                                         { 'default_value' => "LDAPSync,ou=People,${::openldap::base_dn}" }),
  Optional[String]      $syncpw                     = simplib::lookup('simp_options::ldap::sync_hash',{ 'default_value' => undef }),
  String                $binddn                     = simplib::lookup('simp_options::ldap::bind_dn',
                                                        { 'default_value' => "${::openldap::base_dn}" }),
  Optional[String]      $bindpw                     = simplib::lookup('simp_options::ldap::bind_hash',{ 'default_value' => undef }),
  Optional[String]      $suffix                     = $::openldap::base_dn,
  Stdlib::Absolutepath  $argsfile                   = '/var/run/openldap/slapd.args',
  Boolean               $audit_transactions         = true,
  Boolean               $audit_to_syslog            = true,
  Stdlib::Absolutepath  $auditlog                   = '/var/log/slapd.audit',
  String                $auditlog_rotate            = 'daily',
  Integer               $auditlog_preserve          = 7,
  String                $authz_policy               = 'to',
  Array[Hash]           $authz_regexp               = [{
                                                        'match'   => '^uid=([^,]+),.*',
                                                        'replace' => "uid=\$1,ou=People,${::openldap::base_dn}"
                                                      }],
  Boolean               $bind_anon                  = false,
  Integer               $cachesize                  = 10000,
  Pattern['(^\d+\s\d+$|^$)'] $checkpoint                 = '1024 5',
  Array[String]         $trusted_nets               = simplib::lookup('simp_options::trusted_nets',
                                                        { 'default_value' => ['127.0.0.1', '::1'] }),
  String                $concurrency                = '',
  Integer               $conn_max_pending           = 100,
  Integer               $conn_max_pending_auth      = 100,
  Array[String]         $default_schemas            = [ 'openssh-lpk', 'freeradius', 'autofs' ],
  String                $default_searchbase         = '',
  Array[String]         $disallow                   = ['bind_anon','tls_2_anon'],
  Boolean               $force_log_quick_kill       = false,
  String                $ditcontentrule             = '',
  Boolean               $gentlehup                  = false,
  Integer               $idletimeout                = 0,
  Boolean               $include_chain_overlay      = false,
  Integer               $index_substr_any_step      = 2,
  Integer               $index_substr_any_len       = 4,
  Integer               $index_substr_if_maxlen     = 4,
  Integer               $index_substr_if_minlen     = 2,
  Integer               $index_intlen               = 4,
  Boolean               $listen_ldap                = true,
  Boolean               $listen_ldapi               = true,
  Boolean               $listen_ldaps               = true,
  Array                 $custom_options             = [],
  Array[String]         $slapd_logLevel             = ['stats', 'acl', 'sync'],
  String                $password_crypt_salt_format = '%s',
  String                $password_hash              = 'SSHA',
  Stdlib::Absolutepath  $pidfile                    = '/var/run/openldap/slapd.pid',
  Boolean               $reverse_lookup             = false,
  String                $schemadn                   = 'cn=Subschema',
  String                $security                   = 'ssf=256 tls=256 update_ssf=256 simple_bind=256 update_tls=256',
  String                $sizelimit                  = '500',
  String                $sizelimit_soft             = '500',
  String                $sizelimit_hard             = '500',
  String                $sizelimit_unchecked        = '500',
  Integer               $slapd_shutdown_timeout     = 3,
  Integer               $sockbuf_max_incoming       = 262143,
  Integer               $sockbuf_max_incoming_auth  = 4194303,
  Array                 $sortvals                   = [],
  Optional[Integer]     $tcp_buffer                 = undef,
  Variant[Enum['dynamic'],Integer] $threads                    = 'dynamic',
  String                $timelimit                  = '3600',
  String                $timelimit_soft             = '3600',
  String                $timelimit_hard             = '3600',
  Integer               $writetimeout               = 0,
  Variant[Boolean,
         Enum['simp']]  $pki                        = simplib::lookup('simp_options::pki', { 'default_value' => false  }),
  Boolean               $use_tls                    = true,
  Stdlib::Absolutepath  $app_pki_cert_source        = "${::openldap::app_pki_cert_source}",
  Stdlib::Absolutepath  $app_pki_dir                = "${::openldap::app_pki_dir}",
  Stdlib::Absolutepath  $app_pki_ca_dir             = "${::openldap::app_pki_dir}/pki/cacerts",
  Stdlib::Absolutepath  $app_pki_cert               = "${::openldap::app_pki_dir}/pki/public/${::fqdn}.pub",
  Stdlib::Absolutepath  $app_pki_key                = "${::openldap::app_pki_dir}/pki/private/${::fqdn}.pem",
  Array[String]         $tlsCipherSuite             = simplib::lookup('simp_options::openssl::cipher_suite'
                                                        ,{ 'default_value' => ['DEFAULT', '!MEDIUM'] }),
  String                $tlsCRLCheck                = 'none',
  Optional[Stdlib::Absolutepath] $tlsCRLFile                 = undef,
  String                $tlsVerifyClient            = 'try',
  String                $database                   = 'bdb',
  Stdlib::Absolutepath  $directory                  = '/var/lib/ldap',
  Boolean               $db_add_content_acl         = false,
  Boolean               $db_lastmod                 = true,
  Integer               $db_maxderefdepth           = 15,
  Boolean               $db_mirrormode              = false,
  Boolean               $db_monitoring              = true,
  Boolean               $db_readonly                = false,
  String                $db_cachesize               = '0 268435456 1',
  Integer               $db_max_locks               = 3000,
  Integer               $db_max_lock_objects        = 1500,
  Integer               $db_max_lock_lockers        = 1500,
  Integer               $db_log_region_max_size     = 262144,
  Integer               $db_log_buffer_size         = 2097152,
  Boolean               $db_log_autoremove          = true,
  Integer               $ulimit_max_open_files      = 81920,
  Boolean               $syslog                    = simplib::lookup('simp_options::syslog', {'default_value' => false }),
  Boolean               $log_to_file                = false,
  Stdlib::Absolutepath  $log_file                   = '/var/log/slapd.log',
  Boolean               $forward_all_logs           = false,
  Boolean               $firewall                   = simplib::lookup('simp_options::firewall', {'default_value' => false }),
) {
#  validate_array_member($authz_policy,['none','from','to','any'])
#  validate_array_of_hashes($authz_regexp)
#  validate_array_member($password_hash,['SSHA','SHA','SMD5','MD5','CRYPT','CLEARTEXT'])
# Cast threads to a string so it can be regex against both
# digits and the string 'dynamic'
#  validate_re(to_string($threads),'^(\d+|dynamic)$')
#  validate_re($sizelimit,'^(\d+|unlimited)$')
#  validate_re($sizelimit_soft,'^(\d+|unlimited)$')
#  validate_re($sizelimit_hard,'^(\d+|unlimited)$')
#  validate_re($sizelimit_unchecked,'^(\d+|unlimited)$')
#  validate_re($timelimit,'^(\d+|unlimited)$')
#  validate_re($timelimit_soft,'^(\d+|unlimited)$')
#  validate_re($timelimit_hard,'^(\d+|unlimited)$')
#  validate_array_member($tlsCRLCheck,['none','peer','all'])
#  validate_array_member($tlsVerifyClient,['never','allow','try','demand','hard',true])
#  validate_array_member($database,[
#    'bdb',
#    'config',
#    'dnssrv',
#    'hdb',
#    'ldap',
#    'ldif',
#    'meta',
#    'monitor',
#    'null',
#    'passwd',
#    'perl',
#    'relay',
#    'shell',
#    'sql']
#  )
#  validate_re($db_cachesize,'^\d+ \d+ \d+$')

  include '::openldap::server::conf::default_ldif'

  if $pki {

    if $pki == 'simp' { Class['pki'] -> Class['openldap'] }

    pki::copy { "${app_pki_dir}":
      group  => 'ldap',
      source => "${app_pki_cert_source}",
      notify => Class['openldap::server::service'],
      pki    => $pki
    }
  }

  if $::hardwaremodel == 'x86_64' {
      $modulepath = ['/usr/lib64/openldap','/usr/lib/openldap']
  }
  else {
      $modulepath = ['/usr/lib/openldap']
  }

  if $force_log_quick_kill {
    include '::incron'

    incron::system_table { 'nuke_openldap_log_files':
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
    notify  => Class['openldap::server::service']
  }

  file { '/etc/openldap/DB_CONFIG':
    ensure  => 'file',
    owner   => 'root',
    group   => 'ldap',
    mode    => '0640',
    content => template('openldap/etc/openldap/DB_CONFIG.erb'),
    notify  => Class['openldap::server::service']
  }

  if ($::operatingsystem in ['RedHat','CentOS']) and (versioncmp($::operatingsystemmajrelease, '6') > 0) {
    file { '/etc/sysconfig/slapd':
      ensure  => 'file',
      owner   => 'root',
      group   => 'root',
      mode    => '0640',
      content => template('openldap/etc/sysconfig/slapd.erb'),
      notify  => Class['openldap::server::service']
    }
  }
  else {
    file { '/etc/sysconfig/ldap':
      ensure  => 'file',
      owner   => 'root',
      group   => 'root',
      mode    => '0640',
      content => template('openldap/etc/sysconfig/ldap.erb'),
      notify  => Class['openldap::server::service']
    }
  }

  # IPTables
  if $firewall {
    include '::iptables'

    if $listen_ldap or $listen_ldaps {
      iptables::listen::tcp_stateful { 'allow_ldap':
        order        => 11,
        trusted_nets => $trusted_nets,
        dports       => 389
      }
    }
    if $listen_ldaps {
      iptables::listen::tcp_stateful { 'allow_ldaps':
        order        => 11,
        trusted_nets => $trusted_nets,
        dports       => 636
      }
    }
  }

  if $syslog {
    include '::rsyslog'

    if $audit_transactions {
      include '::logrotate'

      file { $auditlog:
        ensure => 'present',
        owner  => 'ldap',
        group  => 'ldap',
        mode   => '0750'
      }

      logrotate::rule { 'slapd_audit_log':
        log_files     => [ $auditlog ],
        create        => '0640 ldap ldap',
        rotate_period => $auditlog_rotate,
        rotate        => $auditlog_preserve
      }

      openldap::server::dynamic_includes::add { 'auditlog':
        order   => 1000,
        content => template('openldap/slapo/auditlog.erb'),
        require => File[$auditlog]
      }

      if $audit_to_syslog {
        include '::rsyslog'
        rsyslog::rule::data_source { 'openldap_audit':
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

        rsyslog::rule::drop { '1_drop_openldap_passwords':
          rule => '
  # Drop passwords from OpenLDAP audit logs.
  if $syslogtag == \'slapd_audit\' and $msg contains \'Password:: \''
        }
      }
    }

    if $log_to_file {
      include '::logrotate'

      # These are quite heavyweight so we're moving them up in the stack.
      rsyslog::rule::local { '05_openldap_local':
        rule            => 'local4.*',
        target_log_file => $log_file
      }

      logrotate::rule { 'slapd':
        log_files  => [ $log_file ],
        missingok  => true,
        lastaction => '/sbin/service rsyslog restart > /dev/null 2>&1 || true'
      }
    }

    if $forward_all_logs {
      rsyslog::rule::remote { '06_openldap_remote':
        rule            => 'if $syslogfacility-text == \'local4\' then',
        stop_processing => true
      }
    }
  }
}
