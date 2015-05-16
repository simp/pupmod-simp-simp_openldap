# == Define: openldap::server::access::add
#
# Add an access control entry to access.conf.
#
# Any variable not described below can be found in slapd.access(5).
#
# == Parameters
#
# [*name*]
# Type: String
#   The unique name of the dynamic include. This does become part of the sort
#   order so be careful!
#
# [*comment*]
# Type: String
#   An arbitrary comment that will be included above the entry.
#
# [*content*]
# Type: String
#   If this is specified, then this will be used as the *entire* content under
#   $what. If you do not specify this, then $who is a required variable.
#
# [*order*]
# Type: Integer
# Default: 1000
#   The default sort order of the entry to be added
#
# == Authors:
#
# * Trevor Vaughan <tvaughan@onyxpoint.com>
#
define openldap::server::access::add (
    $what,
    $comment = '',
    $who = '',
    $access = '',
    $control = '',
    $content = '',
    $order = '1000' )
{
  $l_name = regsubst($name,'/','_')

  concat_fragment { "slapd_access+${order}_${l_name}.inc":
    content => template('openldap/slapd.access.add.erb')
  }

  if empty($who) and empty($content) {
    fail('You must specify "$who" if you are not specifying "$content"')
  }
}
