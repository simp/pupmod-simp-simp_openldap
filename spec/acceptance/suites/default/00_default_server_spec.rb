require 'spec_helper_acceptance'
require 'erb'

test_name 'simp_openldap::server class'

describe 'simp_openldap::server class' do
  servers = hosts_with_role(hosts, 'server')

  let(:server_manifest) {
    <<~EOS
      include 'simp_openldap::server'
    EOS
  }

  hosts.each do |host|
    it 'should disable the firewall' do
      on(host, 'puppet resource service firewalld ensure=stopped')
      on(host, 'puppet resource service iptables ensure=stopped')
    end
  end

  servers.each do |server|
    context "yum repo prep on #{server}" do
      it 'should install SIMP internet repos' do
        install_simp_repos(server)
      end
    end

    # Iteration through different cases for domain component is actually to
    # verify that the client API access (ldapsearch, ldapmodify, ldapadd, etc.)
    # can handle the variation.
    domain_components = [ 'DC', 'dc']
    domain_components.each do |domain_component|
      context "simp_openldap::server #{server} for LDAP domains with '#{domain_component}'" do

        let(:server_fqdn) { fact_on(server, 'fqdn') }
        let(:base_dn) { fact_on(server, 'domain').split('.').map{ |d| "#{domain_component}=#{d}" }.join(',') }

        # It appears when you query ldap it is returning lowercase values for the
        # ldif formats (dn, ou, cn etc) so when the output from a query is checked
        # the lower case format is needed.
        let(:results_base_dn) { fact_on(server, 'domain').split('.').map{ |d| "dc=#{d}" }.join(',') }

        let(:add_testuser)          { File.read(File.expand_path('templates/add_testuser.ldif.erb', File.dirname(__FILE__))) }
        let(:add_testuser_to_admin) { File.read(File.expand_path('templates/add_testuser_to_admin.ldif.erb', File.dirname(__FILE__))) }

        if domain_component != domain_components.first
          context 'ensure clean LDAP environment' do
            it 'should ensure LDAP server configuration is bootstrapped' do
              on(server, 'rm -rf /var/lib/ldap/db/*')
              on(server, 'rm -f /etc/openldap/puppet_bootstrapped.lock')
            end

            it 'should clear out existing LDAP client config that will not regenerate otherwise' do
              on(server, 'rm -f /root/.ldaprc')
            end
          end
        end

        context 'default server parameters (no pki)' do
          let(:hieradata)      { ERB.new(File.read(File.expand_path('templates/hieradata.yaml.erb', File.dirname(__FILE__)))).result(binding) }

          context 'LDAP server configuration' do
            it 'should configure server with tls disabled and with no errors' do
              echo_on(server, base_dn)

              on(server, 'mkdir -p /usr/local/sbin/simp')

              set_hieradata_on(server, hieradata)
              apply_manifest_on(server, server_manifest, :catch_failures => true)
            end

            it 'should be idempotent' do
              apply_manifest_on(server, server_manifest, :catch_changes => true)
            end
          end

          context 'user management on LDAP server' do
            it 'should be able to connect and use ldapsearch' do
              on(server, "ldapsearch -LLL -D cn=LDAPAdmin,ou=People,#{base_dn} -H ldap://#{server_fqdn} -w suP3rP@ssw0r!")
            end

            it 'should be able to add a user' do
              create_remote_file(server, '/tmp/add_testuser.ldif', ERB.new(add_testuser).result(binding))

              on(server, "ldapadd -D cn=LDAPAdmin,ou=People,#{base_dn} -H ldap://#{server_fqdn} -w suP3rP@ssw0r! -x -f /tmp/add_testuser.ldif")

              result = on(server, "ldapsearch -LLL -D cn=LDAPAdmin,ou=People,#{base_dn} -H ldap://#{server_fqdn} -w suP3rP@ssw0r! -x uid=test.user")
              expect(result.stdout).to include("dn: uid=test.user,ou=People,#{results_base_dn}")
            end

            it 'should be able to add user to group' do
              create_remote_file(server, '/tmp/add_testuser_to_admin.ldif', ERB.new(add_testuser_to_admin).result(binding))

              on(server, "ldapmodify -D cn=LDAPAdmin,ou=People,#{base_dn} -H ldap://#{server_fqdn} -w suP3rP@ssw0r! -x -f /tmp/add_testuser_to_admin.ldif")

              result = on(server, "ldapsearch -LLL -D cn=LDAPAdmin,ou=People,#{base_dn} -H ldap://#{server_fqdn} -w suP3rP@ssw0r! -x cn=test.user")
              expect(result.stdout).to include("dn: cn=test.user,ou=Group,#{results_base_dn}")
            end

            context 'should be able to check password complexity' do
              password_list = [
                'p@ssW0rd',      # too short
                'SupErpAssW0rD', # not enough character classes
                'SupRrpassW0rd', # too many character classes in a row
              ]
              password_list.each_with_index do |pass,i|
                it "should reject bad password #{pass}" do
                  sleep(5)
                  result = on(server, "ldappasswd -D uid=test.user,ou=People,#{base_dn} -H ldap://#{server_fqdn} -w 'suP3rP@ssw0r!' -a 'suP3rP@ssw0r!' -s '#{pass}'", :acceptable_exit_codes => [1])
                  expect(result.stdout).to include("Result: Constraint violation (19)")
                end
              end

              # this one should work
              pass = '6q!Bqr3ek^K!9b'
              it "should accept good password #{pass}" do
                sleep(5)
                on(server, "ldappasswd -D uid=test.user,ou=People,#{base_dn} -H ldap://#{server_fqdn} -w 'suP3rP@ssw0r!' -a 'suP3rP@ssw0r!' -s '#{pass}'")
              end
            end

            it 'should be able to expire user passwords using ppolicy' do
             # set clock forward to expire test.user
             # should error out with a password expired message
             on(server, "date --set='next year'; ldapwhoami -D uid=test.user,ou=People,#{base_dn} -H ldap://#{server_fqdn} -x -w suP3rP@ssw0r! -e ppolicy", :acceptable_exit_codes => [49])

             on(server, "date --set='last year'")
            end
          end
        end
      end
    end
  end
end
