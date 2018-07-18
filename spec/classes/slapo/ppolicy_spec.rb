require 'spec_helper'

describe 'simp_openldap::slapo::ppolicy' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end

        let(:params) {{
          :suffix       => 'dn=host,dn=net',
          :use_cracklib => true
        }}

        it { is_expected.to create_package('simp-ppolicy-check-password') }

        it { is_expected.to create_simp_openldap__server__dynamic_include('ppolicy').with_content(
          /ppolicy_default\s+"cn=default,ou=pwpolicies,#{params[:suffix]}"/
        )}

        it {
          conf_name = 'simp_check_password.conf'

          is_expected.to create_file("/etc/openldap/#{conf_name}").with({
            :group    => 'ldap',
            :mode     => '0640',
            :content  => /use_cracklib 1/
          })
        }
      end
    end
  end
end
