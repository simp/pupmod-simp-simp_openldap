require 'spec_helper'

describe 'simp_openldap' do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts) do
          os_facts
        end

        context 'default parameters' do
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_class('simp_openldap') }
          it { is_expected.to create_class('simp_openldap::client') }
          it { is_expected.not_to create_class('simp_openldap::server') }
          it { is_expected.not_to create_pki__copy('openldap') }
        end

        context 'with pki enabled' do
          let(:params) { { pki: 'simp' } }

          it { is_expected.to compile.with_all_deps }
          it {
            is_expected.to create_pki__copy('openldap').with(
              source: '/etc/pki/simp/x509',
              pki: 'simp',
              group: 'root',
            )
          }
        end

        context 'is_server' do
          if os_facts.dig(:os, :release, :major) >= '8'
            it { skip("does not support #{os}") }
            next
          end

          context 'without pki' do
            let(:params) { { is_server: true } }

            it { is_expected.to compile.with_all_deps }
            it { is_expected.to create_class('simp_openldap::server') }
            it { is_expected.not_to create_pki__copy('openldap') }
          end

          context 'with pki' do
            let(:params) { { is_server: true, pki: true } }

            it { is_expected.to compile.with_all_deps }
            it { is_expected.to create_class('simp_openldap::server') }
            it {
              is_expected.to create_pki__copy('openldap').with(
                source: '/etc/pki/simp/x509',
                pki: true,
                group: 'ldap',
              )
            }
          end
        end
      end
    end
  end
end
