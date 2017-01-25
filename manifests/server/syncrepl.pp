# This define configures the sycnrepl functionality of OpenLDAP which allows
# for directory synchronization pulls from a master server.
#
# @see slapd.conf(5)
#
# $name should be the 'rid' of the syncrepl instance and must be between 0 and
# 1000, non-inclusive.
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
#
define simp_openldap::server::syncrepl (
  String[1]                               $syncrepl_retry = '60 10 600 +',
  Optional[String[1]]                     $provider       = simplib::lookup('simp_options::ldap::master', { 'default_value'  => undef }),
  Optional[String[1]]                     $searchbase     = simplib::lookup('simp_options::ldap::base_dn', { 'default_value' => undef }),
  Enum['refreshOnly','refreshAndPersist'] $syncrepl_type  = 'refreshAndPersist',
  Optional[String[1]]                     $interval       = undef,
  Optional[String[1]]                     $filter         = undef,
  String[1]                               $syncrepl_scope = 'sub',
  String[1]                               $attrs          = '*,+',
  Optional[String[1]]                     $attrsonly      = undef,
  Variant[Enum['unlimited'], Integer[0]]  $sizelimit      = 'unlimited',
  Variant[Enum['unlimited'], Integer[0]]  $timelimit      = 'unlimited',
  Enum['on','off']                        $schemachecking = 'off',
  Variant[Enum['critical'], Boolean]      $starttls       = 'critical',
  Enum['simple','sasl']                   $bindmethod     = 'simple',
  Optional[String[1]]                     $binddn         = simplib::lookup('simp_options::ldap::sync_dn', {'default_value'  => undef }),
  Optional[String[1]]                     $saslmech       = undef,
  Optional[String[1]]                     $authcid        = undef,
  Optional[String[1]]                     $authzid        = undef,
  Optional[String[1]]                     $credentials    = simplib::lookup('simp_options::ldap::sync_pw', { 'default_value' => undef }),
  Optional[String[1]]                     $realm          = undef,
  Optional[String[1]]                     $secprops       = undef,
  Optional[String[1]]                     $logbase        = undef,
  Optional[String[1]]                     $logfilter      = undef,
  Enum['default','accesslog']             $syncdata       = 'default',
  Optional[String[1]]                     $updateref      = undef
) {
  if to_integer($name) !~ Integer[1,999] {
    fail('$name must be an integer between `1` and `999`')
  }

  if $provider {
    $_provider = $provider
  }
  elsif $server_facts {
    $_provider = "ldap://${server_facts['servername']}"
  }
  else {
    fail('You must provide a valie for `$provider`')
  }

  validate_re_array(split($syncrepl_retry,'(\d+ \d+)'),'^(\s*(\d+ (\d+|\+)\s*)|\s*)$')

  simp_openldap::server::dynamic_include { 'syncrepl':
    content => template("${module_name}/syncrepl.erb")
  }
}
