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
  String     $syncrepl_retry    = '60 10 600 +',
  String     $provider          = simplib::lookup('simp_options::ldap::master',
                                    { 'default_value' => "ldap://%{hiera('simp_options::puppet::server')}" }),
  String     $searchbase        = simplib::lookup('simp_options::ldap::bind_dn', { 'default_value' => "", 'value_type' => String }),
  String     $syncrepl_type     = 'refreshAndPersist',
  String     $interval          = '',
  String     $filter            = '',
  String     $syncrepl_scope    = 'sub',
  String     $attrs             = '*,+',
  String     $attrsonly         = '',
  String     $sizelimit         = 'unlimited',
  String     $timelimit         = 'unlimited',
  String     $schemachecking    = 'off',
  String     $starttls          = 'critical',
  String     $bindmethod        = 'simple',
  String     $binddn            = simplib::lookup('simp_options::ldap::bind_dn', { 'default_value' => "${::openldap::base_dn}" }),
  String     $saslmech          = '',
  String     $authcid           = '',
  String     $authzid           = '',
  String     $credentials       = simplib::lookup('simp_options::ldap::sync_pw',{ 'default_value' => '' }),
  String     $realm             = '',
  String     $secprops          = '',
  String     $logbase           = '',
  String     $logfilter         = '',
  String     $syncdata          = 'default',
  String     $updateref         = ''
) {
  validate_between($name,'0','1000')
  validate_re_array(split($syncrepl_retry,'(\d+ \d+)'),'^(\s*(\d+ (\d+|\+)\s*)|\s*)$')
  validate_array_member($syncrepl_type,['refreshOnly','refreshAndPersist'])
  if !empty($interval) { validate_integer($interval) }
#  validate_re($sizelimit,'^(\d+|unlimited)$')
#  validate_re($timelimit,'^(\d+|unlimited)$')
  validate_array_member($schemachecking,['on','off'])
  if !empty($starttls) { validate_array_member($starttls,['yes','critical']) }
  if !empty($bindmethod) { validate_array_member($bindmethod,['simple','sasl']) }
  validate_array_member($syncdata,['default','accesslog','changelog'])

  include '::openldap::server::dynamic_includes'

  openldap::server::dynamic_includes::add { 'syncrepl':
    content => template('openldap/syncrepl.erb')
  }
}
