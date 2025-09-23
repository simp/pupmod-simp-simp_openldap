require 'spec_helper'

describe 'simp_openldap::slapo::lastbind' do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts) do
          os_facts
        end
        let(:params) { { lastbind_precision: 3600 } }

        if os_facts.dig(:os, :release, :major) >= '8'
          it { skip("does not support #{os}") }
          next
        end

        it {
          is_expected.to create_file('/etc/openldap/lastbind.conf').with_content(
            "lastbind-precision #{params[:lastbind_precision]}\n",
          )
        }

        it {
          is_expected.to create_simp_openldap__server__dynamic_include('lastbind').that_requires(
            'Package[simp-lastbind]',
          )
        }

        it { is_expected.to create_package('simp-lastbind') }
      end
    end
  end
end
