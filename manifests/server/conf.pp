# **NOTE: THIS IS A [PRIVATE](https://github.com/puppetlabs/puppetlabs-stdlib#assert_private) CLASS**
#
# This class configures the brunt of the ``/etc/openldap`` configuration files
#
# Regarding: POODLE - CVE-2014-3566
#
# Using module defaults and openldap-servers >= 2.4.40, a minimum bound of TLS
# v1.2 will be set.  TLSv1 and SSLv3 ciphers will be removed from the cipher
# suite.
#
# If openldap-servers is < 2.4.40, the ``tls_cipher_suite`` parameter will
# default to ``DEFAULT:!MEDIUM`` because OpenLDAP < 2.4.40 cannot ensure the SSL
# provider natively. Take care to ensure that your clients only connect with
# TLSv1 if possible.
#
# @see slapd.conf(5)
# @see slapd-bdb(5)
#
# @param rootdn
#   The DN of the administrative LDAP user
#
# @param rootpw
#   This is the output of ``slappasswd`` for your LDAP administrative account
#
# @param syncdn
#   The DN of the LDAP synchronization user
#
#   * Used for DB replication
#
# @param syncpw
#   This is the output of ``slappasswd`` for your LDAP sync account
#
# @param binddn
#   The DN of the LDAP host authorization user
#
#   This user should not have the ability to do anything besides bind to the
#   LDAP system for further authentication
#
# @param bindpw
#   This is the output of ``slappasswd`` for your LDAP bind account
#
# @param audit_transactions
#   Set OpenLDAP to audit **all** transactions in the database
#
#   * This will output an LDIF file with all details of what changed on the
#     system and may contain sensitive information
#
# @param audit_to_syslog
#   Forward all audit logs to syslog
#
#   * This may contain sensitive information
#
# @param auditlog
#   The path to the slapd audit log
#
#   * Only effective if ``$audit_transactions`` is enabled
#
# @param auditlog_rotate
#   The frequency with which the slapd audit logs should be rotated
#
# @param auditlog_preserve
#   The number of rotated audit logs to preserve
#
# @param authz_policy
#   Set the appropriate ``authz-policy`` entry
#
# @param authz_regexp
#   Used to convert simple usernames to an LDAP DN for authorization
#
#   * Set to an empty Array ``[]`` to have this value ignored
#   * Entries will be added to the configuration file in order so order them
#     from most strict to least strict in your Array
#   * **NOTE:** The default is fairly lenient
#
# @param default_schemas
#   The default schemas from ``/etc/openldap/schema`` to include
#
#   * ``/etc/openldap/schema`` will be **prepended** and ``.schema`` will be
#     **appended**
#   * It is highly recommended that you keep the default list
#   * If you decide to override, these defaults will *not* be merged with what
#     you provide
#   * ``Core``, ``Cosine``, ``InetOrgPerson``, and ``NIS`` will always be
#     included
#
# @param trusted_nets
#   The networks that should be allowed into the server
#
# @param force_log_quick_kill
#   Create an ``incron`` job that will **immediately** destroy any recovery log
#   file written to the log directory
#
#   * Setting this is not recommended but can be used on systems where you have
#     issues with recovery log size and the way that OpenLDAP manages them
#
# @param include_chain_overlay
#   Include a chain overlay to allow for referral chaining
#
#   * This is only needed on LDAP replicant nodes
#
# @param master
#   If ``include_chain_overlay`` is set, then this is the upstream master that
#   will be used for referral chaining
#
# @param listen_ldap
#   Listen on the default LDAP port for ``ldap://`` conenctions
#
# @param listen_ldapi
#   Listen on the default LDAP port for ``ldapi://`` conenctions
#
# @param listen_ldaps
#   Listen on the default LDAPS port for ``ldaps://`` conenctions
#
# @param custom_options
#   Command line options that will be placed into the openldap configuration
#   file
#
#   * These are **not** validated for correct functionality!
#
# @param password_hash
#   The hash algorithm to use for passwords
#
# @param sizelimit
#   The default size limit for queries
#
#   * If any of the ``$sizelimit_*`` options are set, this will be overridden
#     in ``slapd.conf``
#
# @param sizelimit_soft
#   Corresponds to ``size.soft`` in ``slapd.conf``
#
# @param sizelimit_hard
#   Corresponds to ``size.hard`` in ``slapd.conf``
#
# @param sizelimit_unchecked
#   Corresponds to ``size.unchecked`` in ``slapd.conf``
#
# @param slapd_shutdown_timeout
#   Maximum allowed time to wait for slapd shutdown (in seconds)
#
# @param threads
#   Set the number of threads to run
#
#   * ``dynamic`` sets the limit to ``4 * processorcount``
#   * There is a default minimum of ``8`` and a max of ``16``
#
# @param timelimit
#   The default time limit for queries (in seconds)
#
#   * If any of the ``$timelimit_*`` options are set, this will be overridden
#     in ``slapd.conf``
#
# @param timelimit_soft
#   Corresponds to ``time.soft`` in ``slapd.conf``
#
# @param timelimit_hard
#   Corresponds to ``time.hard`` in ``slapd.conf``
#
# @param tls_protocol_min
#   This option is only compatible with openldap-servers >= 2.4.40.
#
#   From the slapd.conf man page:
#   Specifies minimum SSL/TLS protocol version that will be negotiated.  If the
#   server doesn't  support at least that version, the SSL handshake will fail.
#   To require TLS 1.x or higher, set this option to 3.(x+1), e.g.,
#
#     TLSProtocolMin 3.2
#
#   would require TLS 1.1.
#
# @param tls_verify_client
#   TLS client verification level
#
#   Do not set this more restrictive than 'try' unless you **really** know what
#   you are doing and have exensively tested it in your environment
#
# @param db_cachesize
#   Set the BDB backend cache size
#
#   * The format is ``<gigabytes> <bytes> <segements>``
#
# @param db_log_autoremove
#   Tells the OpenLDAP BDB back end database to automatically remove all
#   recovery log files when possible
#
#   * Setting this means that you are responsible for backing up your database
#     and that incremental recovery may not be possible
#
# @param ulimit_max_open_files
#   Set the number of open file handles that OpenLDAP may use
#
# @param syslog
#   Enable the SIMP logging infrastructure
#
# @param logrotate
#   Enable the SIMP log rotate infrastructure
#
# @param log_to_file
#   Send the output logs to the file specified in ``$log_file``
#
#   * Has no effect if ``$syslog`` is not set
#
# @param log_file
#   Output all logs to this file via syslog
#
#   * Has no effect if ``$log_to_file`` is not set
#
# @param forward_all_logs
#   Forward **all** OpenLDAP logs via syslog
#
#   * Has no effect if ``$syslog`` is not set
#
# @param firewall
#   Enable the SIMP firewall
#
# @param use_tls
#   Enable TLS in openldap. By default this will mirror simp_options::pki,
#   but needs to be distinct as the client and server configurations could vary.
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
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
#
class simp_openldap::server::conf (
  Optional[String[1]]                                 $rootpw                     = undef,
  Optional[String[1]]                                 $syncpw                     = simplib::lookup('simp_options::ldap::sync_hash', { 'default_value' => undef }),
  Optional[String[1]]                                 $bindpw                     = simplib::lookup('simp_options::ldap::bind_hash', { 'default_value' => undef }),
  String[1]                                           $syncdn                     = simplib::lookup('simp_options::ldap::sync_dn', { 'default_value' => "cn=LDAPSync,ou=Hosts,${::simp_openldap::base_dn}" }),
  String[1]                                           $binddn                     = simplib::lookup('simp_options::ldap::bind_dn', { 'default_value' => $::simp_openldap::bind_dn }),
  Optional[String[1]]                                 $rootdn                     = simplib::lookup('simp_options::ldap::root_dn', { 'default_value' => "cn=LDAPAdmin,ou=People,${::simp_openldap::base_dn}" }),
  String[1]                                           $suffix                     = $::simp_openldap::base_dn,
  Stdlib::Absolutepath                                $argsfile                   = '/var/run/openldap/slapd.args',
  Boolean                                             $audit_transactions         = true,
  Boolean                                             $audit_to_syslog            = true,
  Stdlib::Absolutepath                                $auditlog                   = '/var/log/slapd.audit',
  Enum['daily','weekly','monthly','yearly']           $auditlog_rotate            = 'daily',
  Integer[0]                                          $auditlog_preserve          = 7,
  Enum['none','from','to','any']                      $authz_policy               = 'to',
  Boolean                                             $bind_anon                  = false,
  Array[Struct[{
      match   => String[1],
      replace => String[1]
  }] ]                                                $authz_regexp               = [{
                                                          'match'   => '^uid=([^,]+),.*',
                                                          'replace' => "uid=\$1,ou=People,${::simp_openldap::base_dn}"
                                                        }],
  Integer[1]                                          $cachesize                  = 10000,
  Pattern['(^\d+\s\d+$|^$)']                          $checkpoint                 = '1024 5',
  Simplib::Netlist                                    $trusted_nets               = simplib::lookup('simp_options::trusted_nets', { 'default_value' => ['127.0.0.1'] }),
  Optional[Integer[1]]                                $concurrency                = undef,
  Integer[1]                                          $conn_max_pending           = 100,
  Integer[1]                                          $conn_max_pending_auth      = 1000,
  Array[String[1]]                                    $default_schemas            = [ 'openssh-lpk', 'freeradius', 'autofs' ],
  Optional[String[1]]                                 $default_searchbase         = undef,
  Array[Simp_Openldap::SlapdConf::Disallow]           $disallow                   = ['bind_anon','tls_2_anon'],
  Boolean                                             $force_log_quick_kill       = false,
  Optional[String[1]]                                 $ditcontentrule             = undef,
  Boolean                                             $gentlehup                  = false,
  Integer[0]                                          $idletimeout                = 0,
  Boolean                                             $include_chain_overlay      = false,
  Optional[String[1]]                                 $master                     = $::simp_openldap::_ldap_master,
  Integer[0]                                          $index_substr_any_step      = 2,
  Integer[0]                                          $index_substr_any_len       = 4,
  Integer[0]                                          $index_substr_if_maxlen     = 4,
  Integer[0]                                          $index_substr_if_minlen     = 2,
  Integer[0]                                          $index_intlen               = 4,
  Boolean                                             $listen_ldap                = true,
  Boolean                                             $listen_ldapi               = true,
  Boolean                                             $listen_ldaps               = true,
  Array[String]                                       $custom_options             = [],
  Array[Simp_Openldap::LogLevel]                      $slapd_log_level            = ['stats', 'sync'],
  String[1]                                           $password_crypt_salt_format = '%s',
  Enum['SSHA','SHA','SMD5','MD5','CRYPT','CLEARTEXT'] $password_hash              = 'SSHA',
  Stdlib::Absolutepath                                $pidfile                    = '/var/run/openldap/slapd.pid',
  Boolean                                             $reverse_lookup             = false,
  String[1]                                           $schemadn                   = 'cn=Subschema',
  Array[String[1]]                                    $security                   = ['ssf=256', 'tls=256', 'update_ssf=256', 'simple_bind=256', 'update_tls=256'],
  Variant[Enum['unlimited'], Integer[1]]              $sizelimit                  = 500,
  Optional[Variant[Enum['unlimited'], Integer[1]]]    $sizelimit_soft             = undef,
  Optional[Variant[Enum['unlimited'], Integer[1]]]    $sizelimit_hard             = undef,
  Optional[Variant[Enum['unlimited'], Integer[1]]]    $sizelimit_unchecked        = undef,
  Integer[0]                                          $slapd_shutdown_timeout     = 3,
  Integer[1]                                          $sockbuf_max_incoming       = 262143,
  Integer[1]                                          $sockbuf_max_incoming_auth  = 4194303,
  Array[String]                                       $sortvals                   = [],
  Optional[Integer]                                   $tcp_buffer                 = undef,
  Variant[Enum['dynamic'],Integer[1]]                 $threads                    = 'dynamic',
  Variant[Enum['unlimited'], Integer[1]]              $timelimit                  = 3600,
  Optional[Variant[Enum['unlimited'], Integer[1]]]    $timelimit_soft             = undef,
  Optional[Variant[Enum['unlimited'], Integer[1]]]    $timelimit_hard             = undef,
  Integer[0]                                          $writetimeout               = 0,
  Variant[Enum['simp'],Boolean]                       $use_tls                    = $::simp_openldap::pki,
  Stdlib::Absolutepath                                $app_pki_ca_dir             = $::simp_openldap::app_pki_ca_dir,
  Stdlib::Absolutepath                                $app_pki_cert               = $::simp_openldap::app_pki_cert,
  Stdlib::Absolutepath                                $app_pki_key                = $::simp_openldap::app_pki_key,
  Optional[Stdlib::Absolutepath]                      $app_pki_crl                = $::simp_openldap::app_pki_crl,
  Optional[Array[String[1]]]                          $tls_cipher_suite           = undef,
  Optional[Float]                                     $tls_protocol_min           = undef,
  Enum['none','peer','all']                           $tls_crl_check              = 'none',
  # lint:ignore:quoted_booleans
  Enum['never','allow','try','demand','hard','true']  $tls_verify_client          = 'allow',
  # lint:endignore
  String[1]                                           $database                   = 'bdb',
  Stdlib::Absolutepath                                $directory                  = '/var/lib/ldap',
  Boolean                                             $db_add_content_acl         = false,
  Boolean                                             $db_lastmod                 = true,
  Integer[1]                                          $db_maxderefdepth           = 15,
  Boolean                                             $db_mirrormode              = false,
  Boolean                                             $db_monitoring              = true,
  Boolean                                             $db_readonly                = false,
  Pattern['^\d+\s\d+\s\d+$']                          $db_cachesize               = '0 268435456 1',
  Integer[1]                                          $db_max_locks               = 3000,
  Integer[1]                                          $db_max_lock_objects        = 1500,
  Integer[1]                                          $db_max_lock_lockers        = 1500,
  Integer[1]                                          $db_log_region_max_size     = 262144,
  Integer[1]                                          $db_log_buffer_size         = 2097152,
  Boolean                                             $db_log_autoremove          = true,
  Integer[1024]                                       $ulimit_max_open_files      = 81920,
  Boolean                                             $syslog                     = simplib::lookup('simp_options::syslog', {'default_value' => false }),
  Boolean                                             $logrotate                  = simplib::lookup('simp_options::logrotate', {'default_value' => false }),
  Boolean                                             $log_to_file                = false,
  Stdlib::Absolutepath                                $log_file                   = '/var/log/slapd.log',
  Boolean                                             $forward_all_logs           = false,
  Boolean                                             $firewall                   = simplib::lookup('simp_options::firewall', {'default_value' => false }),
) inherits ::simp_openldap {

  include '::simp_openldap::server::conf::default_ldif'

  if $force_log_quick_kill {
    include '::incron'

    incron::system_table { 'nuke_openldap_log_files':
      path    => "${directory}/logs",
      mask    => ['IN_CREATE'],
      command => '/bin/rm $@/$#'
    }
  }

  # By default, remove weak ciphers and allow users to set a minimum TLS
  # protocol if openlap supports it
  if $tls_cipher_suite {
    $_tls_cipher_suite = $tls_cipher_suite
  }
  if $facts['slapd_version'] {
    if $facts['slapd_version'] >= '2.4.40' {
      if $tls_protocol_min {
        $_tls_protocol_min = $tls_protocol_min
      }
      # Minimum bound of TLSv1.2
      else {
        $_tls_protocol_min = '3.3'
      }
      # If the minimum TLS bound is > TLSv1, remove weak protocols
      if !defined('$_tls_cipher_suite') and $_tls_protocol_min >= '3.1' {
        $_tls_cipher_suite = ['HIGH','-TLSv1', '-SSLv3']
      }
    }
    else {
      if $tls_protocol_min {
        notify { 'TLSProtocolMin':
          message => "TLSProtocolMin not supported by openldap-servers ${facts['slapd_version']}"
        }
      }
    }
  }
  # Fallback if cipher suite not specified and we can't determine the version
  # of slapd
  if !defined('$_tls_cipher_suite') {
    $_tls_cipher_suite = simplib::lookup('simp_options::openssl::cipher_suite' ,{ 'default_value' =>  ['DEFAULT', '!MEDIUM'] })
  }

  file { '/etc/openldap/slapd.conf':
    ensure  => 'file',
    owner   => 'root',
    group   => 'ldap',
    mode    => '0640',
    content => template("${module_name}/etc/openldap/slapd.conf.erb"),
  }

  file { '/etc/openldap/DB_CONFIG':
    ensure  => 'file',
    owner   => 'root',
    group   => 'ldap',
    mode    => '0640',
    content => template("${module_name}/etc/openldap/DB_CONFIG.erb"),
  }

  if versioncmp($facts['os']['release']['major'], '6') > 0 {
    file { '/etc/sysconfig/slapd':
      ensure  => 'file',
      owner   => 'root',
      group   => 'root',
      mode    => '0640',
      content => template("${module_name}/etc/sysconfig/slapd.erb"),
    }
  }
  else {
    file { '/etc/sysconfig/ldap':
      ensure  => 'file',
      owner   => 'root',
      group   => 'root',
      mode    => '0640',
      content => template("${module_name}/etc/sysconfig/ldap.erb"),
    }
  }

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

      simp_openldap::server::dynamic_include { 'auditlog':
        order   => 1000,
        content => template("${module_name}/slapo/auditlog.erb"),
        require => File[$auditlog]
      }

      if $audit_to_syslog {
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

        # Drop passwords from OpenLDAP audit logs.
        rsyslog::rule::drop { '1_drop_openldap_passwords':
          rule => '$syslogtag == \'slapd_audit\' and $msg contains \'Password:: \''
        }
      }
    }

    if $log_to_file {
      include '::logrotate'

      # These are quite heavyweight so we're moving them up in the stack.
      rsyslog::rule::local { '05_openldap_local':
        rule            => "prifilt('local4.*')",
        target_log_file => $log_file
      }

      if $logrotate {
        logrotate::rule { 'slapd':
          log_files                 => [ $log_file ],
          missingok                 => true,
          lastaction_restart_logger => true
        }
      }
    }

    if $forward_all_logs {
      rsyslog::rule::remote { '06_openldap_remote':
        rule            => '$syslogfacility-text == \'local4\'',
        stop_processing => true
      }
    }
  }
}
