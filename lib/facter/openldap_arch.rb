# _Description_
#
# Return the architecture of the installed OpenLDAP package
#
Facter.add("openldap_arch") do
    setcode do
        retval = "i386"

        if FileTest.exists?("/usr/sbin/slapd") then

            if ( %x{/usr/bin/file /usr/sbin/slapd} =~ /64-bit/ ) then
                retval = "x86_64"
            end
        end

        retval
    end
end
