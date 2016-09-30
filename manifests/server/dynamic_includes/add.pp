# == Define: opneldap::server::dynamic_includes::add
#
# Add a dynamically included file into the LDAP system.
#
# [*name*]
# Type: String
#   A unique name of the dynamic include
#
# [*content*]
# Type: String
#   The literal content of the dynamic include
#
# [*order*]
# Type: Integer
# Default: 100
#   The numeric order of the dynamic include
#
# == Authors:
#
# * Trevor Vaughan <tvaughan@onyxpoint.com>
#
define openldap::server::dynamic_includes::add (
    $content,
    $order = '100' )
{
  $l_name = regsubst($name,'/','_')

  simpcat_fragment { "slapd_dynamic_includes+${order}_${l_name}.inc":
    content => $content
  }
}
