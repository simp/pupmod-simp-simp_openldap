# Set a fact to return the version of slapd that is installed
#
Facter.add('slapd_version') do
  slapd_bin = Facter::Core::Execution.which('slapd')
  setcode do
    if slapd_bin
      out = Facter::Core::Execution.execute("#{slapd_bin} -VV 2>&1")
      out =~ %r{slapd (\d+\.\d+\.\d+)}
      Regexp.last_match(1)
    end
  end
end
