# Add a dynamically included file into the LDAP system.
#
# @attr name [String]
#   A unique name for the resource
#
# @param content
#   The literal content of the dynamic include
#
# @param order
#   The numeric order of the dynamic include
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
#
define simp_openldap::server::dynamic_include (
  String  $content,
  Integer $order = 100
) {
  ensure_resource('concat', '/etc/openldap/dynamic_includes', {
    owner          => 'root',
    group          => 'ldap',
    mode           => '0640',
    ensure_newline => true,
    warn           => true,
  })

  concat::fragment { "openldap_dynamic_include_${name}":
    target  => '/etc/openldap/dynamic_includes',
    content => $content
  }
}
