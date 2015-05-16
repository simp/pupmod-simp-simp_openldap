# == Class: openldap::slapo::lastbind
#
# This class configures lastbind and set up a dynamic include that defines lastbind.
# See slapo-lastbind(5) for details of the options.
#
# == Parameters
#
# [*lastbind_precision*]
#   String.  Determines the amount of time, in seconds, after which to update the
#   auth timestamp entry.
#
# == Authors
#
# * Nick Markowski <nmarkowski@keywcorp.com>
# * Kendall Moore <kmoore@keywcorp.com>
#
class openldap::slapo::lastbind (
# $lastbind_precision
#     The value <in seconds> after which to update the authTimestamp
    $lastbind_precision = '3600'
) {
  include 'openldap::server::dynamic_includes'

  file { '/etc/openldap/lastbind.conf':
    owner   => 'root',
    group   => 'ldap',
    mode    => '0640',
    content => "lastbind-precision $lastbind_precision\n",
    require => Package['simp-lastbind']
  }

  openldap::server::dynamic_includes::add { 'lastbind':
    order   => '1000',
    content => "moduleload lastbind.so\noverlay lastbind\n",
    require => Package['simp-lastbind']
  }

  package { 'simp-lastbind': ensure => 'latest' }
}
