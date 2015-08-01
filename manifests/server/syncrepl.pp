# == Class: openldap::server:;syncrepl
#
# This define configures the sycnrepl functionality of OpenLDAP which allows
# for directory synchronization pulls from a master server.
#
# All variables are defined in the 'syncrepl' section of slapd.conf(5).
#
# $name should be the 'rid' of the syncrepl instance and must be
# between 0 and 1000 non-inclusive.
#
# == Authors
#
# * Trevor Vaughan <tvaughan@onyxpoint.com>
#
define openldap::server::syncrepl (
  $syncrepl_retry = '60 10 600 +',
  $provider = hiera('ldap::master'),
  $searchbase = hiera('ldap::base_dn'),
  $syncrepl_type='refreshAndPersist',
  $interval='',
  $filter='',
  $syncrepl_scope='sub',
  $attrs='*,+',
  $attrsonly='',
  $sizelimit='unlimited',
  $timelimit='unlimited',
  $schemachecking='off',
  $starttls='critical',
  $bindmethod='simple',
  $binddn=hiera('ldap::sync_dn',''),
  $saslmech='',
  $authcid='',
  $authzid='',
  $credentials=hiera('ldap::sync_pw',''),
  $realm='',
  $secprops='',
  $logbase='',
  $logfilter='',
  $syncdata='default',
  $updateref=''
) {
  validate_between($name,'0','1000')
  validate_re_array(split($syncrepl_retry,'(\d+ \d+)'),'^(\s*(\d+ (\d+|\+)\s*)|\s*)$')
  validate_array_member($syncrepl_type,['refreshOnly','refreshAndPersist'])
  if !empty($interval) { validate_integer($interval) }
  validate_re($sizelimit,'^(\d+|unlimited)$')
  validate_re($timelimit,'^(\d+|unlimited)$')
  validate_array_member($schemachecking,['on','off'])
  if !empty($starttls) { validate_array_member($starttls,['yes','critical']) }
  if !empty($bindmethod) { validate_array_member($bindmethod,['simple','sasl']) }
  validate_array_member($syncdata,['default','accesslog','changelog'])

  include '::openldap::server::dynamic_includes'

  openldap::server::dynamic_includes::add { 'syncrepl':
    content => template('openldap/syncrepl.erb')
  }
}
