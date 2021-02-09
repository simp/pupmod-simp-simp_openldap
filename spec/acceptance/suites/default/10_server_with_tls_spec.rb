require 'spec_helper_acceptance'
require 'erb'

test_name 'simp_openldap::server with tls'

describe 'simp_openldap::server with tls' do
  servers = hosts_with_role(hosts, 'server')

  let(:server_manifest) {
    <<-EOS
      include 'simp_openldap::server'
    EOS
  }

  servers.each do |server|
    context "simp_openldap::server #{server}" do
      let(:server_fqdn) { fact_on(server, 'fqdn') }
      let(:base_dn) { fact_on(server, 'domain').split('.').map{ |d| "dc=#{d}" }.join(',') }

      context 'with tls enabled' do
        let(:hieradata)  { ERB.new(File.read(File.expand_path('templates/hieradata_tls.yaml.erb', File.dirname(__FILE__)))).result(binding) }

        shared_examples_for 'a tls enabled system' do
          it 'should be able to connect using tls and use ldapsearch' do
            on(server, "ldapsearch -ZZ -LLL -D cn=LDAPAdmin,ou=People,#{base_dn} -H ldap://#{server_fqdn} -x -w suP3rP@ssw0r!")
          end

          it 'should reject non-tls connections' do
            on(server, "ldapsearch -LLL -D cn=LDAPAdmin,ou=People,#{base_dn} -H ldap://#{server_fqdn} -x -w suP3rP@ssw0r!", :acceptable_exit_codes=> [13])
          end

          it 'should only accept tlsv1.2 connections' do
            result = on(server, "echo 'Q' | openssl s_client -connect localhost:636 -tls1_2")

            expect(result.stdout).to include('Server certificate')
            ['tls1','tls1_1'].each do |cipher|
              result = on(server,
                "echo 'Q' | openssl s_client -connect localhost:636 -#{cipher}",
                :acceptable_exit_codes => 1
              )
            end
            result = on(server,
              "echo 'Q' | openssl s_client -connect localhost:636 -ssl3",
              :acceptable_exit_codes => 1
            )
          end
        end

        context 'LDAP server configuration' do
          # /root/.ldaprc was created by a previous test and will not
          # be overwritten because of 'replace => false' in the file resource.
          # Needs to be configured with certs info.
          it 'should remove /root/.ldaprc so it will be created with certs info' do
            on(server, 'rm -f /root/.ldaprc')
          end

          it 'should configure server with tls enabled and with no errors' do
            set_hieradata_on(server, hieradata)
            apply_manifest_on(server, server_manifest, :catch_failures => true)
          end

          it 'should be idempotent' do
            apply_manifest_on(server, server_manifest, :catch_changes => true)
          end

          it_should_behave_like 'a tls enabled system'
        end

        context 'with a new set of PKI certificates' do
          it 'should populate new certificates into simp-testing' do
            Dir.mktmpdir do |cert_dir|
              run_fake_pki_ca_on(server, hosts, cert_dir)
              hosts.each { |sut| copy_pki_to(sut, cert_dir, '/etc/pki/simp-testing') }
            end
          end

          # Refresh the certs via Puppet
          it 'should reconfigure LDAP server with new certs' do
            apply_manifest_on(server, server_manifest, :catch_failures => true)
          end

          it_should_behave_like 'a tls enabled system'
        end
      end
    end
  end
end
