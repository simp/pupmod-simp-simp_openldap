# This class configures lastbind and set up a dynamic include that defines lastbind.
# See slapo-lastbind(5) for details of the options.
#
# @param lastbind_precision
#   Determines the amount of time, in seconds, after which to update the
#   authTimestamp entry.
#
# @param lastbind_ensure The ensure status of packages to be managed
#
# @author https://github.com/simp/pupmod-simp-simp_openldap/graphs/contributors
#
class simp_openldap::slapo::lastbind (
  Integer[0] $lastbind_precision = 3600,
  String     $lastbind_ensure     = simplib::lookup('simp_options::package_ensure', { 'default_value' => 'installed' }),
) {

  package { 'simp-lastbind':
    ensure => $lastbind_ensure
  }

  file { '/etc/openldap/lastbind.conf':
    owner   => 'root',
    group   => 'ldap',
    mode    => '0640',
    content => "lastbind-precision ${lastbind_precision}\n",
    require => Package['simp-lastbind']
  }

  simp_openldap::server::dynamic_include { 'lastbind':
    order   => 1000,
    content => "moduleload lastbind.so\noverlay lastbind\n",
    require => Package['simp-lastbind']
  }
}
