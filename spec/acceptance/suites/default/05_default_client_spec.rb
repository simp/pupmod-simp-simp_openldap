require 'spec_helper_acceptance'
require 'erb'

test_name 'simp_openldap class'

describe 'simp_openldap class' do
  servers = hosts_with_role(hosts, 'server')
  clients = hosts_with_role(hosts, 'client')

  let(:client_manifest) do
    <<~EOS
      include 'simp_openldap'
    EOS
  end

  servers.each do |server|
    context "default client parameters (no pki) when LDAP server #{server}" do
      let(:server_fqdn) { fact_on(server, 'fqdn') }
      let(:base_dn) { fact_on(server, 'domain').split('.').map { |d| "dc=#{d}" }.join(',') }
      let(:hieradata) { ERB.new(File.read(File.expand_path('templates/hieradata.yaml.erb', File.dirname(__FILE__)))).result(binding) }

      clients.each do |client|
        context "LDAP client configuration for #{client}" do
          it 'configures client with tls disabled and with no errors' do
            set_hieradata_on(client, hieradata)
            apply_manifest_on(client, client_manifest, catch_failures: true)
          end

          it 'is idempotent' do
            apply_manifest_on(client, client_manifest, catch_changes: true)
          end
        end

        context 'client connection to the LDAP server' do
          it 'is able to connect using the bind DN and password' do
            # LDAP server parameters are set in /etc/openldap/ldap.conf by simp_openldap
            bind_dn = "cn=hostAuth,ou=Hosts,#{base_dn}"
            bind_pw = 'foobarbaz'
            result = on(client, "ldapsearch -D #{bind_dn} -w #{bind_pw}")
            expect(result.output).to match(%r{dn: uid=test\.user,ou=People,})
          end
        end
      end
    end
  end
end
