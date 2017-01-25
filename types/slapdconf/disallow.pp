# OpenLDAP slapd.conf disallow
type Simp_Openldap::SlapdConf::Disallow = Enum[
  'bind_anon',
  'bind_simple',
  'tls_2_anon',
  'tls_authc',
  'proxy_authz_non_critical',
  'dontusecopy_non_critical'
]
