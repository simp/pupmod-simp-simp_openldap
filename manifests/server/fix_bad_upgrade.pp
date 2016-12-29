# Fix the slapd.d upgrade cycle that we're not currently ready for.
#
# This pops up in the RPM updates from time to time.
#
class openldap::server::fix_bad_upgrade {

  assert_private()

  # We're not ready for using slapd.d.
  # Occasionally, the updated openldap RPM packages come out with an
  # automatic upgrade to slapd.d functionality. This works around
  # having your system destroyed by that "feature".
  exec { 'fix_bad_upgrade':
    command => '/bin/rm -rf /etc/openldap/slapd.d && \
      if [ -f /etc/openldap/slapd.conf.bak ]; then \
        /bin/mv /etc/openldap/slapd.conf.bak /etc/openldap.slapd.conf; \
      fi',
    require => Package["openldap-servers.${::hardwaremodel}"],
    notify  => File['/var/lib/ldap/DB_CONFIG'],
    onlyif  => '/usr/bin/test -d /etc/openldap/slapd.d',
    before  => [
      Exec['bootstrap_ldap'],
      File['/etc/openldap/slapd.conf']
    ]
  }
}
