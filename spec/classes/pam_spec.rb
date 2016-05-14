require 'spec_helper'

describe 'openldap::pam' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          if ['RedHat','CentOS'].include?(facts[:operatingsystem]) && facts[:operatingsystemmajrelease].to_s < '7'
            facts[:grub_version] = '0.9'
          else
            facts[:grub_version] = '2.0~beta'
          end

          facts
        end

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to create_class('auditd') }
        it {
          is_expected.to create_auditd__add_rules('ldap.conf').with({
            :content => /CFG_etc_ldap/
          })
          is_expected.to create_auditd__add_rules('ldap.conf').that_requires('File[/etc/pam_ldap.conf]')
        }
        it { is_expected.to create_class('pki').that_comes_before('File[/etc/pam_ldap.conf]') }
        it {
          if (['RedHat', 'CentOS'].include?(facts[:operatingsystem])) && (facts[:operatingsystemrelease].to_s < '6.7')
            is_expected.to create_class('nscd')
            is_expected.to create_group('nslcd')
            is_expected.to create_file('/etc/nslcd.d').that_requires('Group[nslcd]')
            is_expected.to create_file('/etc/nslcd.conf').with({
              :content => /tls_cert\s+\/etc\/nslcd.d\/pki\/public\/#{facts[:fqdn]}.pub/,
              :content => /tls_key\s+\/etc\/nslcd.d\/pki\/private\/#{facts[:fqdn]}.pem/,
              :content => /tls_cacertdir\s+\/etc\/nslcd.d\/pki\/cacerts/,
              :content => /tls_cacertfile\s+\/etc\/nslcd.d\/pki\/cacerts\/cacerts.pem/
            })
            is_expected.to create_service('nslcd').with({
              :require => ['File[/etc/nslcd.conf]','File[/etc/nslcd.d]']
            })
            is_expected.to create_pki__copy('/etc/nslcd.d').that_requires('File[/etc/nslcd.d]')
          else
            is_expected.to create_class('sssd')
          end
        }
        it {
          is_expected.to create_file('/etc/pam_ldap.conf').with({ :content => /ssl\s+start_tls/ })
          is_expected.to create_file('/etc/pam_ldap.conf').with({ :content => /binddn\s+.+/ })
          is_expected.to create_file('/etc/pam_ldap.conf').with({ :content => /bindpw\s+.+/ })
          is_expected.to create_file('/etc/pam_ldap.conf').with({ :content => /tls_checkpeer yes/ })
        }
        it { is_expected.to contain_package("nss-pam-ldapd") }
        it { is_expected.to contain_package("openldap-clients.#{facts[:hardwaremodel]}") }

        context 'no_auditd' do
          let(:params){{ :use_auditd => false }}

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to_not create_auditd__add_rules('ldap.conf') }
        end

        context 'no_pki and use_simp_pki=false' do
          let(:params){{
            :ssl            => false,
            :use_simp_pki   => false,
            :tls_cacertfile => '/etc/nslcd.d/foopki/cacerts/cacerts.pem',
            :tls_cacertdir  => '/etc/nslcd.d/foopki/cacerts',
            :tls_key        => '/etc/nslcd.d/foopki/fookey.pem',
            :tls_cert       => '/etc/nslcd.d/foopki/foocert.pub'
          }}

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to_not create_class('pki').that_comes_before('File[/etc/pam_ldap.conf]') }
          if (['RedHat', 'CentOS'].include?(facts[:operatingsystem])) && (facts[:operatingsystemrelease].to_s < '6.7')
            it {
              is_expected.to create_file('/etc/nslcd.conf').with({
                :content => /tls_cert\s+\/etc\/nslcd.d\/foopki\/public\/foocert.pub/,
                :content => /tls_key\s+\/etc\/nslcd.d\/foopki\/private\/fookey.pem/,
                :content => /tls_cacertdir\s+\/etc\/nslcd.d\/foopki\/cacerts/,
                :content => /tls_cacertfile\s+\/etc\/nslcd.d\/foopki\/cacerts\/cacerts.pem/
              })
            }
          end
          it { is_expected.to_not create_pki__copy('/etc/nslcd.d') }
        end

        context 'use_sssd' do
          let(:params){{
            :use_sssd => true
          }}

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_class('sssd') }
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_file('/etc/pam_ldap.conf') }
          it { is_expected.to_not create_service('nscd').with_enable(true) }
          it { is_expected.to_not create_service('nslcd') }
        end

        context 'threads_is_default' do
          it {
            if (['RedHat', 'CentOS'].include?(facts[:operatingsystem])) && (facts[:operatingsystemrelease].to_s < '6.7')
              is_expected.to create_file('/etc/nslcd.conf').with({ :content => /threads 5/ })
            else
              is_expected.to_not create_file('/etc/nslcd.conf')
            end
          }
        end

        context 'threads_is_user_overridden' do
          let(:params){{
            :threads => 20
          }}

          it {
            if (['RedHat', 'CentOS'].include?(facts[:operatingsystem])) && (facts[:operatingsystemrelease].to_s < '6.7')
              is_expected.to create_file('/etc/nslcd.conf').with({ :content => /threads 20/ })
              is_expected.to create_file('/etc/nslcd.conf').without({ :content => /threads 5/ })
            else
              is_expected.to_not create_file('/etc/nslcd.conf')
            end
          }
        end
      end
    end
  end
end
