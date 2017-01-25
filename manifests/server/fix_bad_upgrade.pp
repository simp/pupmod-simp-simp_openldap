# **NOTE: THIS IS A [PRIVATE](https://github.com/puppetlabs/puppetlabs-stdlib#assert_private) CLASS**
#
# We're not ready for using slapd.d
#
# Occasionally, the updated openldap RPM packages come out with an automatic
# upgrade to slapd.d functionality.
#
# This works around having your system destroyed by that "feature"
#
# This pops up in the RPM updates from time to time
#
class simp_openldap::server::fix_bad_upgrade {
  assert_private()

  exec { 'fix_bad_upgrade':
    command => '/bin/rm -rf /etc/openldap/slapd.d && \
      if [ -f /etc/openldap/slapd.conf.bak ]; then \
        /bin/mv /etc/openldap/slapd.conf.bak /etc/openldap.slapd.conf; \
      fi',
    require => Package["openldap-servers.${facts['hardwaremodel']}"],
    notify  => File['/var/lib/ldap/DB_CONFIG'],
    onlyif  => '/usr/bin/test -d /etc/openldap/slapd.d',
    before  => [
      Exec['bootstrap_ldap'],
      File['/etc/openldap/slapd.conf']
    ]
  }
}
