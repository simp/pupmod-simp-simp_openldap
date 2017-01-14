# Allow other LDAP servers to synchronize with this one
#
# @see slapo-syncprov(5)
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
#
class openldap::slapo::syncprov (
  Optional[Pattern['^\d+\s\d+$']]     $checkpoint           = undef,
  Optional[String[1]]                 $sessionlog           = undef,
  Boolean                             $nopresent            = false,
  Boolean                             $reloadhint           = false,
  Variant[Enum['unlimited'], Integer] $sync_size_soft_limit = 'unlimited',
  Variant[Enum['unlimited'], Integer] $sync_size_hard_limit = 'unlimited',
  Variant[Enum['unlimited'], Integer] $sync_time_soft_limit = 'unlimited',
  Variant[Enum['unlimited'], Integer] $sync_time_hard_limit = 'unlimited'
) {
  include '::openldap::server'

  openldap::server::dynamic_include { 'syncprov':
    order   => 1000,
    content => template("${module_name}/slapo/syncprov.erb")
  }

  openldap::server::limits { 'Allow Sync User Unlimited':
    who    => $::openldap::server::sync_dn,
    limits => [
      "size.soft=${sync_size_soft_limit}",
      "size.hard=${sync_size_hard_limit}",
      "time.soft=${sync_time_soft_limit}",
      "time.hard=${sync_time_hard_limit}"
    ]
  }
}
