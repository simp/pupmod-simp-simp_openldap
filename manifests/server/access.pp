# Manage access control entries in ``slapd.access``
#
# Remember that **order matters**! Entries will be listed in alphanumeric order
# after the ``$order`` parameter is processed.
#
# @see slapd.access(5)
#
# @param name
#   The unique name of the dynamic include. This does become part of the sort
#   order so be careful!
#
# @param comment
#   An arbitrary comment that will be included above the entry
#
#   * You do not need to include the leading `#`
#
# @param content
#   the **entire* content under ``$what``
#
#   * If you do not specify this, ``$who`` is a required variable
#   * If you do specify this, ``$who`` will be ignored
#
# @param order
#   The default sort order of the entry to be added
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
#
define simp_openldap::server::access (
  String           $what,
  Optional[String] $comment = undef,
  Optional[String] $who     = undef,
  Optional[String] $access  = undef,
  Optional[String] $control = undef,
  Optional[String] $content = undef,
  Integer          $order   = 1000
) {
  ensure_resource('concat', '/etc/openldap/slapd.access', {
    owner          => 'root',
    group          => 'ldap',
    mode           => '0640',
    ensure_newline => true,
    warn           => true,
    order          => 'numeric',
    notify         => Class['simp_openldap::server::service']
  })

  unless ($who or $content) {
    fail('You must specify "$who" if you are not specifying "$content"')
  }

  if $content {
    $_content = "access to ${what} ${content}"
  }
  else {
    if $comment {
      if $comment =~ Pattern['^#'] {
        $_comment = "\n${comment}\n"
      }
      else {
        $_comment = "\n# ${comment}\n"
      }
    }
    else {
      $_comment = ''
    }

    $_optional_content = join(map([$access, $control]) |$x| {
      if $x {
        " ${x}"
      }
      else {
        ''
      }
    }, '')

    $_content = "${_comment}access to ${what}\n    by ${who}${_optional_content}"
  }

  concat::fragment { "openldap_access_${name}":
    target  => '/etc/openldap/slapd.access',
    content => $_content,
    order   => $order
  }
}
