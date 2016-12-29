# This class configures lastbind and set up a dynamic include that defines lastbind.
# See slapo-lastbind(5) for details of the options.
#
# @param lastbind_precision
#   Determines the amount of time, in seconds, after which to update the
#   authTimestamp entry.
#
# @author Nick Markowski <nmarkowski@keywcorp.com>
# @author Kendall Moore <kmoore@keywcorp.com>
#
class openldap::slapo::lastbind (
  Integer $lastbind_precision = 3600
) {
  include 'openldap::server::dynamic_includes'

  file { '/etc/openldap/lastbind.conf':
    owner   => 'root',
    group   => 'ldap',
    mode    => '0640',
    content => "lastbind-precision ${lastbind_precision}\n",
    require => Package['simp-lastbind']
  }

  openldap::server::dynamic_includes::add { 'lastbind':
    order   => 1000,
    content => "moduleload lastbind.so\noverlay lastbind\n",
    require => Package['simp-lastbind']
  }

  package { 'simp-lastbind': ensure => 'latest' }
}
