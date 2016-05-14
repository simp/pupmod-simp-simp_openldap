require 'spec_helper'

describe 'openldap::client' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end

        it { is_expected.to create_class('openldap') }
        it { is_expected.to create_class('openldap::client') }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to create_file('/etc/openldap/ldap.conf').with_content(/TLS_CIPHER_SUITE\s+HIGH:-SSLv2/) }
        it { is_expected.to create_file('/root/.ldaprc') }
      end
    end
  end
end
