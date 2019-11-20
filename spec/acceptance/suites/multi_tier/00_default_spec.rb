require 'spec_helper_acceptance'
require 'erb'

test_name 'simp_openldap tiering'

describe 'simp_openldap class' do
  let(:base_dn) { fact_on(host, 'domain').split('.').map{ |d| "dc=#{d}" }.join(',') }

  # These entries match the node names in the nodeset so don't change them
  # randomly!
  let(:hieradata_overlay){{
    'yggdrasil' => {
      # Only for the tests
      'test_admin_pass'                     => 'suP3rP@ssw0r!',
      # End only for the tests
      'simp_options::ldap::bind_pw'         => 'foobarbaz',
      'simp_options::ldap::bind_hash'       => '{SSHA}ioOP+/DQKe6sl1pt5yX6KvxNHFeyHQ1A',
      'simp_openldap::server::conf::rootpw' => '{SSHA}wcRAktSgNQo+uyMEsmYfqvcCP8Aad3oI'
    },
    'valhalla'  => {
      # Only for the tests
      'test_admin_pass'                     => 'suP3rP@ssw0r!!',
      'test_sync_pass'                      => 'valhalla sync',
      'test_sync_hash'                      => '{SSHA}P6lPXkL9Q4/lIiqgFE/bMuCndhe7gftT',
      # End only for the tests
      'simp_options::ldap::base_dn'         => "ou=Valhalla,#{base_dn}",
      'simp_options::ldap::bind_dn'         => "cn=hostAuth,ou=Hosts,ou=Valhalla,#{base_dn}",
      'simp_options::ldap::bind_pw'         => 'foobarbaz1',
      'simp_options::ldap::bind_hash'       => '{SSHA}xas+n3P2Qa827CSP+IHNtYAkwSIHsAja',
      # This is needed for full stack replication from the top level directory
      'simp_openldap::server::conf::suffix' => base_dn,
      'simp_openldap::server::conf::rootdn' => "cn=LDAPAdmin,ou=People,ou=Valhalla,#{base_dn}",
      'simp_openldap::server::conf::rootpw' => '{SSHA}xjDEC/doD94vevJ9sFwI9gbqvVe69MJr'
    },
    'niflheim'  => {
      # Only for the tests
      'test_admin_pass'                     => 'suP3rP@ssw0r!!!',
      'test_sync_pass'                      => 'niflheim sync',
      'test_sync_hash'                      => '{SSHA}UN5mMFLfjrjcWbufKUH1r4o5XI+FyNWW',
      # End only for the tests
      'simp_options::ldap::base_dn'         => "ou=Niflheim,#{base_dn}",
      'simp_options::ldap::bind_dn'         => "cn=hostAuth,ou=Hosts,ou=Niflheim,#{base_dn}",
      'simp_options::ldap::bind_pw'         => 'foobarbaz2',
      'simp_options::ldap::bind_hash'       => '{SSHA}UoKntkxjUv/LIitnLJudT30lNDXMAtpM',
      # This is needed for full stack replication from the top level directory
      'simp_openldap::server::conf::suffix' => base_dn,
      'simp_openldap::server::conf::rootdn' => "cn=LDAPAdmin,ou=People,ou=Niflheim,#{base_dn}",
      'simp_openldap::server::conf::rootpw' => '{SSHA}PZ2g82WSOC1pG251UdLVLQIkPRyEHeVH'
    }
  }}

  let(:server_fqdn) { fact_on(host, 'fqdn') }
  let(:server_domain) { fact_on(host, 'domain') }

  let(:admin_pw) {
    if hieradata_overlay[host.name]
      hieradata_overlay[host.name]['test_admin_pass']
    end
  }

  let(:bind_pw) {
    if hieradata_overlay[host.name]
      hieradata_overlay[host.name]['simp_options::ldap::bind_pw']
    end
  }

  let(:sync_pw) {
    if hieradata_overlay[host.name]
      hieradata_overlay[host.name]['test_sync_pass']
    end
  }

  let(:server_manifest) {
    if host[:roles].include?('ldap_root')
      manifest = <<-EOS
        include 'simp_openldap::server'

        include 'simp_openldap::server'
        include 'simp_openldap::slapo::ppolicy'
        include 'simp_openldap::slapo::syncprov'

        $_base_dn = simplib::lookup('simp_options::ldap::base_dn')

        $valhalla_sync_dn = "cn=LDAPSync,ou=Hosts,ou=Valhalla,${_base_dn}"
        $valhalla_sync_pw = '#{hieradata_overlay['valhalla']['simp_openldap::server::conf::rootpw']}'

        $niflheim_sync_dn = "cn=LDAPSync,ou=Hosts,ou=Niflheim,${_base_dn}"
        $niflheim_sync_pw = '#{hieradata_overlay['niflheim']['simp_openldap::server::conf::rootpw']}'

        simp_openldap::server::limits { 'Host_Bind_DN_Unlimited_Query':
          who    => simplib::lookup('simp_options::ldap::bind_dn'),
          limits => ['size.soft=unlimited','size.hard=unlimited','size.prtotal=unlimited']
        }

        simp_openldap::server::limits { 'LDAP_Sync_Valhalla_Unlimited_Query':
          who    => $valhalla_sync_dn,
          limits => ['size.soft=unlimited','size.hard=unlimited','size.prtotal=unlimited']
        }

        simp_openldap::server::limits { 'LDAP_Sync_Niflheim_Unlimited_Query':
          who    => $niflheim_sync_dn,
          limits => ['size.soft=unlimited','size.hard=unlimited','size.prtotal=unlimited']
        }

        simp_openldap::server::access { 'LDAP_Auth_Sync_Valhalla':
          what    => "dn.exact=\\"cn=LDAPSync,ou=Hosts,ou=Valhalla,${_base_dn}\\" attrs=\\"userPassword\\"",
          content => "by anonymous auth",
          order   => 10
        }

        simp_openldap::server::access { 'LDAP_Sync_Valhalla':
          what    => "dn.subtree=\\"ou=Valhalla,${_base_dn}\\"",
          content => "by dn.exact=\\"${valhalla_sync_dn}\\" read",
          order   => 10
        }

        simp_openldap::server::access { 'LDAP_Auth_Sync_Niflheim':
          what    => "dn.exact=\\"cn=LDAPSync,ou=Hosts,ou=Niflheim,${_base_dn}\\" attrs=\\"userPassword\\"",
          content => "by anonymous auth",
          order   => 10
        }

        simp_openldap::server::access { 'LDAP_Sync_Niflheim':
          what    => "dn.subtree=\\"ou=Niflheim,${_base_dn}\\"",
          content => "by dn.exact=\\"${niflheim_sync_dn}\\" read",
          order   => 10
        }

        # These override the settings in simp_openldap::server to allow a regexp
        # match for the LDAPSync accounts. We're using the 'first match wins'
        # functionality of slapd.access to effect this

        simp_openldap::server::access { 'override_userpassword_access':
          what    => 'attrs=userPassword',
          content => "
            by dn.regex=\\"cn=LDAPSync,(.+,)?ou=Hosts,${_base_dn}\\" read
            by dn.exact=\\"${simp_openldap::bind_dn}\\" read
            by anonymous auth
            by self write
            by * none",
          order   => 100
        }

        simp_openldap::server::access { 'override_shadowlastchange_access':
          what    => 'attrs=shadowLastChange',
          content => "
            by dn.regex=\\"cn=LDAPSync,(.+,)?ou=Hosts,${_base_dn}\\" read
            by dn.exact=\\"${simp_openldap::bind_dn}\\" read
            by anonymous auth
            by self write
            by * none",
          order   => 100
        }

      EOS
    elsif host.name == 'valhalla'
      manifest = <<-EOS
        include simp_openldap::server
        include simp_openldap::slapo::ppolicy
        include simp_openldap::slapo::syncprov

        $_base_dn = simplib::lookup('simp_options::ldap::base_dn')

        simp_openldap::server::syncrepl { '555':
          binddn      => "cn=LDAPSync,ou=Hosts,${_base_dn}",
          credentials => '#{sync_pw}',
          # This needs to be the top level so that all of the account aliases work
          searchbase  => '#{base_dn}'
        }

        simp_openldap::server::limits { 'Host_Bind_DN_Unlimited_Query':
          who    => simplib::lookup('simp_options::ldap::bind_dn'),
          limits => ['size.soft=unlimited','size.hard=unlimited','size.prtotal=unlimited']
        }
      EOS
    else
      manifest = <<-EOS
        include simp_openldap::server
        include simp_openldap::slapo::ppolicy
        include simp_openldap::slapo::syncprov

        $_base_dn = simplib::lookup('simp_options::ldap::base_dn')

        simp_openldap::server::syncrepl { '556':
          binddn      => "cn=LDAPSync,ou=Hosts,${_base_dn}",
          credentials => '#{sync_pw}',
          # This needs to be the top level so that all of the account aliases work
          searchbase  => '#{base_dn}'
        }

        simp_openldap::server::limits { 'Host_Bind_DN_Unlimited_Query':
          who    => simplib::lookup('simp_options::ldap::bind_dn'),
          limits => ['size.soft=unlimited','size.hard=unlimited','size.prtotal=unlimited']
        }
      EOS
    end

    manifest
  }

  let(:user_data) { File.read(File.expand_path('templates/root_node/add_data.ldif.erb', __dir__)) }
  let(:admin_data) { File.read(File.expand_path('templates/root_node/update_admin_group.ldif.erb', __dir__)) }

  let(:server_hieradata) {
    template_data = YAML.load(
      ERB.new(File.read(File.expand_path('templates/root_node/server_hieradata.yaml.erb', __dir__))).result(binding)
    )

    if hieradata_overlay[host.name]
      template_data.merge!(hieradata_overlay[host.name])
    end

    template_data
  }

  hosts.each do |server|
    context "on #{server}" do
      let(:host) { server }

      context 'preparing for run' do
        it 'should configure server with no errors' do
          echo_on(server, base_dn)

          on(server, 'mkdir -p /usr/local/sbin/simp')

          set_hieradata_on(server, server_hieradata)
          apply_manifest_on(server, server_manifest, :catch_failures => true)
          on(server, 'slapcat')

          apply_manifest_on(server, server_manifest, :catch_failures => true)
        end

        xit 'should be idempotent' do
          apply_manifest(server_manifest, {:catch_changes => true})
        end
      end
    end
  end

  hosts_with_role(hosts, 'ldap_root').each do |server|
    context "on #{server}" do
      let(:host) { server }

      it 'should be able to connect and use ldapsearch' do
        on(server, "ldapsearch -ZZ -LLL -D cn=LDAPAdmin,ou=People,#{base_dn} -H ldap://#{server_fqdn} -w '#{admin_pw}'")
      end

      it 'should be able to add user data' do
        create_remote_file(server, '/tmp/user_data.ldif', ERB.new(user_data).result(binding))

        on(server, "ldapadd -ZZ -D cn=LDAPAdmin,ou=People,#{base_dn} -H ldap://#{server_fqdn} -w '#{admin_pw}' -x -f /tmp/user_data.ldif")

        result = on(server, "ldapsearch -ZZ -LLL -D cn=LDAPAdmin,ou=People,#{base_dn} -H ldap://#{server_fqdn} -w '#{admin_pw}' -x uid=odin")
        expect(result.stdout).to include("dn: uid=odin,ou=People,#{base_dn}")
      end

      it 'should add users to the admin group' do
        create_remote_file(server, '/tmp/admin_data.ldif', ERB.new(admin_data).result(binding))

        on(server, "ldapmodify -ZZ -D cn=LDAPAdmin,ou=People,#{base_dn} -H ldap://#{server_fqdn} -w '#{admin_pw}' -x -f /tmp/admin_data.ldif")

        result = on(server, "ldapsearch -ZZ -LLL -D cn=LDAPAdmin,ou=People,#{base_dn} -H ldap://#{server_fqdn} -w '#{admin_pw}' -x cn=odin")
        expect(result.stdout).to include("dn: cn=odin,ou=Group,#{base_dn}")
      end
    end
  end

  hosts_with_role(hosts, 'valhalla').each do |server|
    context "on Valhalla #{server}" do
      let(:host) { server }

      it 'should restart the service to trigger a sync' do
        on(host, 'puppet resource service slapd ensure=stopped')
        on(host, 'puppet resource service slapd ensure=running')
      end

      it 'should have only allowed entries in the database' do
        result = on(host, 'slapcat').output.strip

        expect(result).to_not match(/ou=Niflheim/m)
      end

      it 'should be able to query the local server as the bind user' do
        expect(on(server, "ldapsearch -ZZ -LLL -D cn=hostAuth,ou=Hosts,ou=Valhalla,#{base_dn} -H ldap://#{server_fqdn} -w '#{bind_pw}'").stdout).to match(/dn: uid=thor,ou=People,ou=Valhalla,#{base_dn}/m)
      end
    end
  end

  hosts_with_role(hosts, 'niflheim').each do |server|
    context "on Niflheim #{server}" do
      let(:host) { server }

      it 'should restart the service to trigger a sync' do
        on(host, 'puppet resource service slapd ensure=stopped')
        on(host, 'puppet resource service slapd ensure=running')
      end

      it 'should have only allowed entries in the database' do
        result = on(host, 'slapcat').output.strip

        expect(result).to_not match(/ou=Valhalla/m)
      end

      it 'should be able to query the local server as the bind user' do
        expect(on(server, "ldapsearch -ZZ -LLL -D cn=hostAuth,ou=Hosts,ou=Niflheim,#{base_dn} -H ldap://#{server_fqdn} -w '#{bind_pw}'").stdout).to match(/dn: uid=mimir,ou=People,ou=Niflheim,#{base_dn}/m)
      end
    end
  end
end
