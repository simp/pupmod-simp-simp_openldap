require 'spec_helper_acceptance'
require 'erb'

test_name 'simp_openldap with tls'

describe 'simp_openldap with tls' do
  servers = hosts_with_role(hosts, 'server')
  clients = hosts_with_role(hosts, 'client')

  let(:client_manifest) do
    <<~EOS
      include 'simp_openldap'
    EOS
  end

  servers.each do |server|
    context "client with tls  when LDAP server #{server}" do
      let(:server_fqdn) { fact_on(server, 'fqdn') }
      let(:base_dn) { fact_on(server, 'domain').split('.').map { |d| "dc=#{d}" }.join(',') }
      let(:hieradata) { ERB.new(File.read(File.expand_path('templates/hieradata_tls.yaml.erb', File.dirname(__FILE__)))).result(binding) }

      clients.each do |client|
        context "client #{client} configuration" do
          # /root/.ldaprc was created by a previous test and will not
          # be overwritten because of 'replace => false' in the file resource.
          # Needs to be configured with certs info.
          it 'removes /root/.ldaprc so it will be created with certs info' do
            on(client, 'rm -f /root/.ldaprc')
          end

          it 'configures client with tls and with no errors' do
            set_hieradata_on(client, hieradata)
            apply_manifest_on(client, client_manifest, catch_failures: true)
          end

          it 'is idempotent' do
            apply_manifest_on(client, client_manifest, catch_changes: true)
          end
        end

        context 'connection to the LDAP server' do
          it 'is able to connect using TLS' do
            # LDAP server and cert parameters are set in /etc/openldap/ldap.conf
            # and /root/.ldaprc by simp_openldap
            result = on(client, 'ldapsearch -ZZ')
            expect(result.output).to match(%r{dn: uid=test\.user,ou=People,})
          end
        end
      end
    end
  end
end
