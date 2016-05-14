require 'spec_helper'

describe 'openldap::server::access' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end

        it { is_expected.to create_class('openldap::server') }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to create_concat_build('slapd_access').that_notifies('Exec[postprocess_slapd.access]') }
        it { is_expected.to create_exec('postprocess_slapd.access').that_requires('File[/usr/local/sbin/simp/build_slapd_access.rb]') }
        it { is_expected.to create_file('/usr/local/sbin/simp/build_slapd_access.rb') }
        it {
          is_expected.to create_file('/etc/openldap/slapd.access').with({
            :require => 'Exec[postprocess_slapd.access]',
            :notify  => 'Class[Openldap::Server::Service]',
            :source  => /file:\/\/.*slapd.access.out/
          })
        }
      end
    end
  end
end
