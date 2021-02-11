require 'spec_helper_acceptance'
require 'erb'

test_name 'simp-ppolicy-check-password update test'

describe 'simp-ppolicy-check-password update' do
  servers = hosts_with_role(hosts, 'server')

  servers.each do |server|
    context "on server #{server}" do
      let(:server_fqdn) { fact_on(server, 'fqdn') }
      let(:base_dn) { fact_on(server, 'domain').split('.').map{ |d| "dc=#{d}" }.join(',') }

      # The ldif format always comes out in lowercase when quering the openldap server
      let(:results_base_dn) { fact_on(server, 'domain').split('.').map{ |d| "dc=#{d}" }.join(',') }

      context 'on the clean server' do
        it 'should be running openldap' do
          on(server, "puppet resource service slapd ensure=running")
        end

        it 'should be using the latest simp-ppolicy-check-password package' do
          on(server, 'puppet resource package simp-ppolicy-check-password ensure=latest')
          on(server, "puppet resource service slapd ensure=stopped")
          on(server, "puppet resource service slapd ensure=running")
        end

        it 'should have a test user from a previous test' do
          result = on(server, "ldapsearch -Z -LLL -D cn=LDAPAdmin,ou=People,#{base_dn} -H ldap://#{server_fqdn} -w suP3rP@ssw0r! -x cn=test.user")
          expect(result.stdout).to include("dn: cn=test.user,ou=Group,#{results_base_dn}")
        end
      end

      context 'when updating openldap' do
        it 'should update openldap' do
          on(server, 'yum update -y openldap*')
          server.reboot
        end

        it 'should be running openldap' do
          on(server, "puppet resource service slapd ensure=running")
        end

        it 'should be able to access the test user' do
          result = on(server, "ldapsearch -Z -LLL -D cn=LDAPAdmin,ou=People,#{base_dn} -H ldap://#{server_fqdn} -w suP3rP@ssw0r! -x cn=test.user")
          expect(result.stdout).to include("dn: cn=test.user,ou=Group,#{results_base_dn}")
        end
      end
    end
  end
end
