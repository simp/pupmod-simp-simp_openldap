# Allow other LDAP servers to synchronize with this one.
#
# All parameters are defined in slapo-syncprov(5).
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
#
class openldap::slapo::syncprov (
  Pattern['(^\d+\s\d+$|^$)']         $checkpoint           = '',
  String                             $sessionlog           = '',
  Boolean                            $nopresent            = false,
  Boolean                            $reloadhint           = false,
  Variant[Enum['unlimited'],Integer] $sync_size_soft_limit = 'unlimited',
  Variant[Enum['unlimited'],Integer] $sync_size_hard_limit = 'unlimited',
  Variant[Enum['unlimited'],Integer] $sync_time_soft_limit = 'unlimited',
  Variant[Enum['unlimited'],Integer] $sync_time_hard_limit = 'unlimited'
) {
  include 'openldap::server::dynamic_includes'

  openldap::server::dynamic_includes::add { 'syncprov':
    order   => 1000,
    content => template('openldap/slapo/syncprov.erb')
  }

  openldap::server::add_limits { 'Allow Sync User Unlimited':
    who    => hiera('ldap::sync_dn',$::openldap::server::sync_dn),
    limits => [
      "size.soft=${sync_size_soft_limit}",
      "size.hard=${sync_size_hard_limit}",
      "time.soft=${sync_time_soft_limit}",
      "time.hard=${sync_time_hard_limit}"
    ]
  }

#  if !empty($checkpoint) { validate_re($checkpoint,'\d+ \d+') }
#  if !empty($sessionlog) { validate_integer($sessionlog) }
}
