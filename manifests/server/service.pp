#
# == Class: openldap::server::service
#
# This class manages the OpenLDAP service.
#
class openldap::server::service (
  $slapd_svc = 'slapd'
){
  assert_private()

  include '::openldap::server::fix_bad_upgrade'

  # This is a very crude attempt to not bootstrap if the executing
  # node is a slave node. Bootstrapping slave nodes causes the
  # 'administrators' group to become unable to sync if it doesn't
  # start identical to the master.
  exec { 'bootstrap_ldap':
    command   => "/sbin/service ${slapd_svc} stop; \
        /bin/find /var/lib/ldap -type f -name \"__db*\" -exec /bin/rm {} \\;; \
        /bin/find /var/lib/ldap/db -type f -name \"*bdb\" -exec /bin/rm {} \\;; \
        /usr/sbin/slapadd -l /etc/openldap/default.ldif -f /etc/openldap/slapd.conf; \
        /bin/chown -h -R ldap.ldap /var/lib/ldap/*; \
        /bin/touch /etc/openldap/puppet_bootstrapped.lock; \
        /bin/chown root:ldap /etc/openldap/puppet_bootstrapped.lock; \
        /bin/echo 'Bootstrapped LDAP';",
    onlyif    => '/usr/local/sbin/ldap_bootstrap_check.sh',
    logoutput => true,
    require   => [
      File['/etc/openldap/schema'],
      File['/usr/local/sbin/ldap_bootstrap_check.sh'],
    ],
    creates   => '/etc/openldap/puppet_bootstrapped.lock',
    notify    => Service[$slapd_svc],
    before    => Exec['fixperms']
  }

  # Ensure all of /var/lib/ldap is owned by ldap.
  exec { 'fixperms':
    command => '/bin/chown -h -R ldap.ldap /var/lib/ldap/*;',
    onlyif  => '/usr/bin/test `/bin/find /var/lib/ldap -printf "%u\n" | \
      /bin/grep -v ldap | \
      /usr/bin/wc -l` -ne 0',
    notify  => Service[$slapd_svc]
  }

  service { $slapd_svc:
    ensure     => 'running',
    enable     => true,
    hasrestart => true,
    hasstatus  => true,
    require    => [
      Package["openldap-servers.${::hardwaremodel}"],
      Class['openldap::server::fix_bad_upgrade']
    ]
  }
}
