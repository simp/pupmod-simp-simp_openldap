require 'spec_helper'

describe 'openldap' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts[:server_facts] = {
            :servername => facts[:fqdn],
            :serverip   => facts[:ipaddress]
          }
          facts
        end

        it { is_expected.to create_class('openldap') }
        it { is_expected.to compile.with_all_deps }

        context 'is_server' do
          let(:params) {{
            :is_server => true
          }}

          it { is_expected.to create_class('openldap::server') }
        end
      end
    end
  end
end
