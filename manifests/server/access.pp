# This is a helper class for adding access control rules to
# /etc/openldap/slapd.access.
#
# This whole thing needs to be rewritten as a native type.
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
#
class openldap::server::access {
  include '::openldap::server'

  $fragdir = simpcat_fragmentdir('slapd_access')

  simpcat_build { 'slapd_access':
    order  => '*.inc',
    target => "${fragdir}_slapd.access",
    notify => Exec['postprocess_slapd.access']
  }

  exec { 'postprocess_slapd.access':
    command => "/usr/local/sbin/simp/build_slapd_access.rb ${fragdir}_slapd.access",
    unless  => "/usr/bin/diff -q ${fragdir}_slapd.access.out /etc/openldap/slapd.access",
    require => File['/usr/local/sbin/simp/build_slapd_access.rb']
  }

  file { '/usr/local/sbin/simp/build_slapd_access.rb':
    owner   => 'root',
    group   => 'root',
    mode    => '0750',
    content => template('openldap/build_slapd_access.rb.erb')
  }

  file { '/etc/openldap/slapd.access':
    ensure  => 'file',
    owner   => 'root',
    group   => 'ldap',
    mode    => '0640',
    require => Exec['postprocess_slapd.access'],
    notify  => Class['openldap::server::service'],
    source  => "file://${fragdir}_slapd.access.out"
  }
}
