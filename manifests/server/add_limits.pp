# == Define: openldap::server::add_limits
#
# This define allows you to all 'limits' sections under the main database.
#
# See slapd.conf(5) for details.
#
# == Parameters:
#
# [*name*]
# Type: String
#   A unique name for the limits entry.
#
# [*who*]
#   Any of the following values (not validated)
#   *                          All, including anonymous and authenticated users
#   anonymous                  Anonymous (non-authenticated) users
#   users                      Authenticated users
#   self                       User associated with target entry
#   dn[.<basic-style>]=<regex> Users matching a regular expression
#   dn.<scope-style>=<DN>      Users within scope of a DN
#   group[/oc[/at]]=<pattern>  Members of a group
#
# [*limits*]
#   Type: Array
#     A list of limits to apply to $who per slapd.conf(5)
#
# == Authors:
#
# * Trevor Vaughan <tvaughan@onyxpoint.com>
#
define openldap::server::add_limits (
  $who,
  $limits
) {

  include 'openldap::server::dynamic_includes'

  $l_name = regsubst($name,'/','_')
  $l_limits = join($limits,' ')

  openldap::server::dynamic_includes::add { "limit_${l_name}":
    content => "limits ${who} ${l_limits}\n"
  }

  validate_array($limits)
}
