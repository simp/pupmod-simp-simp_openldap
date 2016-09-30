require 'spec_helper'

describe 'openldap::server::dynamic_includes' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end

        it { is_expected.to create_simpcat_build('slapd_dynamic_includes').with({
            :target => '/etc/openldap/dynamic_includes',
            :before => 'Exec[bootstrap_ldap]'
          })
        }
      end
    end
  end
end
