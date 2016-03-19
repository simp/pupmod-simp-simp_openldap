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

        it { should compile.with_all_deps }
        it { should create_class('auditd') }
        it {
          should create_auditd__add_rules('ldap.conf').with({
            :content => /CFG_etc_ldap/
          })
          should create_auditd__add_rules('ldap.conf').that_requires('File[/etc/pam_ldap.conf]')
        }
        it { should create_class('pki').that_comes_before('File[/etc/pam_ldap.conf]') }
        it {
          if (['RedHat', 'CentOS'].include?(facts[:operatingsystem])) && (facts[:operatingsystemrelease].to_s < '6.7')
            should create_class('nscd')
          else
            should create_class('sssd')
          end
        }
        it {
          should create_file('/etc/pam_ldap.conf').with({ :content => /ssl\s+start_tls/ })
          should create_file('/etc/pam_ldap.conf').with({ :content => /binddn\s+.+/ })
          should create_file('/etc/pam_ldap.conf').with({ :content => /bindpw\s+.+/ })
          should create_file('/etc/pam_ldap.conf').with({ :content => /tls_checkpeer yes/ })
        }
        it { should contain_package("nss-pam-ldapd") }
        it { should contain_package("openldap-clients.#{facts[:hardwaremodel]}") }
    
        context 'no_auditd' do
          let(:params){{ :use_auditd => false }}
    
          it { should compile.with_all_deps }
          it { should_not create_auditd__add_rules('ldap.conf') }
        end
    
        context 'no_pki' do
          let(:params){{ :ssl => false }}
    
          it { should compile.with_all_deps }
          it { should_not create_class('pki').that_comes_before('File[/etc/pam_ldap.conf]') }
        end
    
        context 'use_sssd' do
          let(:params){{
            :use_sssd => true
          }}
    
          it { should compile.with_all_deps }
          it { should create_class('sssd') }
          it { should compile.with_all_deps }
          it { should create_file('/etc/pam_ldap.conf') }
          it { should_not create_service('nscd').with_enable(true) }
          it { should_not create_service('nslcd') }
        end
    
        context 'threads_is_default' do
          it {
            if (['RedHat', 'CentOS'].include?(facts[:operatingsystem])) && (facts[:operatingsystemrelease].to_s < '6.7')
              should create_file('/etc/nslcd.conf').with({ :content => /threads 5/ })
            else
              should_not create_file('/etc/nslcd.conf')
            end
          }
        end
    
        context 'threads_is_user_overridden' do
          let(:params){{
            :threads => 20
          }}
    
          it { 
            if (['RedHat', 'CentOS'].include?(facts[:operatingsystem])) && (facts[:operatingsystemrelease].to_s < '6.7')
              should create_file('/etc/nslcd.conf').with({ :content => /threads 20/ })
              should create_file('/etc/nslcd.conf').without({ :content => /threads 5/ })
            else
              should_not create_file('/etc/nslcd.conf')
            end
          }
        end
      end
    end
  end
end
