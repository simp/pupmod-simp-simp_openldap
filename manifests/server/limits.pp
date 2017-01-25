# This define allows you to manage ``limits`` sections under the **main**
# database
#
# @see slapd.conf(5)
#
# @param name
#   A unique name for the limits entry
#
# @param who
#   Any of the following values (not validated)
#     * ``*``                          All, including anonymous and authenticated users
#     * ``anonymous``                  Anonymous (non-authenticated) users
#     * ``users``                      Authenticated users
#     * ``self``                       User associated with target entry
#     * ``dn[.<basic-style>]=<regex>`` Users matching a regular expression
#     * ``dn.<scope-style>=<DN>``      Users within scope of a DN
#     * ``group[/oc[/at]]=<pattern>``  Members of a group
#
# @param limits
#   A list of limits to apply to ``$who`` per ``slapd.conf(5)``
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
#
define simp_openldap::server::limits (
  String                        $who,
  Variant[Array[String],String] $limits
) {
  if $limits =~ Array {
    $_limits = join($limits,' ')
  }
  else {
    $_limits = $limits
  }

  simp_openldap::server::dynamic_include { "limit_${name}":
    content => "limits ${who} ${_limits}"
  }
}
