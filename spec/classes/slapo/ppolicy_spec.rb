require 'spec_helper'

describe 'simp_openldap::slapo::ppolicy' do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts) do
          os_facts
        end
        let(:params) do
          {
            suffix: 'dn=host,dn=net',
         use_cracklib: true,
          }
        end

        if os_facts.dig(:os, :release, :major) >= '8'
          it { skip("does not support #{os}") }
          next
        end

        it { is_expected.to create_package('simp-ppolicy-check-password') }

        it {
          is_expected.to create_simp_openldap__server__dynamic_include('ppolicy').with_content(
          %r{ppolicy_default\s+"cn=default,ou=pwpolicies,#{params[:suffix]}"},
        )
        }

        it {
          conf_name = 'simp_check_password.conf'

          is_expected.to create_file("/etc/openldap/#{conf_name}").with({
                                                                          group: 'ldap',
            mode: '0640',
            content: %r{use_cracklib 1},
                                                                        })
        }
      end
    end
  end
end
