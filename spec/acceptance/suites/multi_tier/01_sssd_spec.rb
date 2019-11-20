require 'spec_helper_acceptance'
require 'erb'

test_name 'simp_openldap tiering sssd validation'

describe 'simp_openldap with sssd' do

  let(:hieradata) {{
    'sssd::domains'              => ['LDAP'],
    'sssd::services'             => ['nss', 'pam'],
    # If you leave purging on, slapd certs will be removed
    'pki::copy::apps_dir::purge' => false
  }}

  let(:manifest) {
    <<-HEREDOC
      include sssd
      include sssd::service::nss
      include sssd::service::pam

      sssd::domain { 'LDAP':
        description               => 'LDAP',
        id_provider               => 'ldap',
        auth_provider             => 'ldap',
        chpass_provider           => 'ldap',
        access_provider           => 'ldap',
        min_id                    => 1000,
        use_fully_qualified_names => false,
        # Just for the tests
        enumerate                 => true
      }

      $pki_key_root = simplib::lookup('simp_options::pki::source')

      sssd::provider::ldap { 'LDAP':
        # Needed for alias support
        ldap_deref      => 'always',
        ldap_user_gecos => 'dn',
        ldap_id_mapping => false,
        app_pki_ca_dir  => "${pki_key_root}/cacerts",
        app_pki_key     => "${pki_key_root}/private/${facts['fqdn']}.pem",
        app_pki_cert    => "${pki_key_root}/public/${facts['fqdn']}.pub"
      }
    HEREDOC
  }

  hosts.each do |host|
    context "on #{host}" do
      if host[:roles].include?('ldap_root')
        let(:user_hash) {
          {
            'odin'      => '10000',
            'freyja'    => '10001',
            'thor'      => '10002',
            'loki'      => '10003',
            'ymir'      => '20000',
            'thrivaldi' => '20001',
            'mimir'     => '20002',
            'nfsnobody' => '65534'
          }
        }

        let(:group_hash){ user_hash }

      elsif host[:roles].include?('valhalla')
        let(:user_hash) {
          {
            'freyja'    => '10001',
            'thor'      => '10002',
            'loki'      => '10003',
            'nfsnobody' => '65534'
          }
        }

        let(:group_hash){ user_hash.merge({'valhalla' => '30000'}) }

      elsif host[:roles].include?('niflheim')
        let(:user_hash) {
          {
            'ymir'      => '20000',
            'thrivaldi' => '20001',
            'mimir'     => '20002',
            'nfsnobody' => '65534'
          }
        }

        let(:group_hash){ user_hash.merge({'niflheim' => '40000'}) }
      end

      it 'should configure sssd with no errors' do
        current_hieradata = YAML.safe_load(file_contents_on(host, File.join(hiera_datadir(host), 'common.yaml')))

        set_hieradata_on(host, current_hieradata.merge(hieradata))
        apply_manifest_on(host, manifest, :catch_failures => true)

        # Contents change after SSSD gets installed based on 'best guess' defaults
        apply_manifest_on(host, manifest, :catch_failures => true)
      end

      it 'should be idempotent' do
        apply_manifest_on(host, manifest, {:catch_changes => true})
      end

      it 'should have the expected user entries' do
        passwd = on(host, 'getent passwd').output.lines
        passwd.map!{|x| x.strip.split(':').values_at(0,3)}
        passwd.delete_if{|uname, uid| uid.to_i < 1001}

        expect(Hash[passwd]).to eq(user_hash)
      end

      it 'should have the expected group entries' do
        group = on(host, 'getent group').output.lines
        group.map!{|x| x.strip.split(':').values_at(0,2)}
        group.delete_if{|gname, gid| gid.to_i < 1001}

        expect(Hash[group]).to eq(group_hash)
      end
    end
  end
end
