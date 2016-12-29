# Add a dynamically included file into the LDAP system.
#
# @param name
#   A unique name of the dynamic include
#
# @param content
#   The literal content of the dynamic include
#
# @param order
#   The numeric order of the dynamic include
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
#
define openldap::server::dynamic_includes::add (
    String  $content,
    Integer $order = 100
) {
  $l_name = regsubst($name,'/','_')

  simpcat_fragment { "slapd_dynamic_includes+${order}_${l_name}.inc":
    content => $content
  }
}
