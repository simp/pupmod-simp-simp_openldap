# OpenLDAP Log Levels
type Simp_Openldap::LogLevel = Variant[
  Integer[-1,65535],
  Enum[
  'any',
  '-',
  'trace',
  'packets',
  'args',
  'conns',
  'BER',
  'ber',
  'filter',
  'config',
  'ACL',
  'acl',
  'stats',
  'stats2',
  'shell',
  'parse',
  'cache',
  'index',
  'sync',
  'none'
]]
