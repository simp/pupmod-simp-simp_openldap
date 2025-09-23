# _Description_
#
# Return the architecture of the installed OpenLDAP package
#
Facter.add('openldap_arch') do
  setcode do
    retval = 'i386'

    if FileTest.exist?('/usr/sbin/slapd')

      if `/usr/bin/file /usr/sbin/slapd`.include?('64-bit')
        retval = 'x86_64'
      end
    end

    retval
  end
end
