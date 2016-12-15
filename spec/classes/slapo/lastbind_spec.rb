require 'spec_helper'

describe 'openldap::slapo::lastbind' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end

        let(:params) {{ :lastbind_precision => 3600 }}

        it { is_expected.to create_class('openldap::server::dynamic_includes') }

        it { is_expected.to create_file('/etc/openldap/lastbind.conf').with_content(
          "lastbind-precision #{params[:lastbind_precision]}\n"
        )}

        it { is_expected.to create_openldap__server__dynamic_includes__add('lastbind').that_requires(
          'Package[simp-lastbind]'
        )}

        it { is_expected.to create_package('simp-lastbind') }
      end
    end
  end
end
