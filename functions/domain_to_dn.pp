function openldap::domain_to_dn (
  String $domain = $facts['domain']
) {
  join(split($domain,'\.').map |$x| { "dc=${x}" }, ',')
}
