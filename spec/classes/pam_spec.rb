require 'spec_helper'

describe 'openldap::pam' do
  base_facts = {
    "RHEL 6" => {
      :fqdn => 'spec.test',
      :grub_version => '0.97',
      :hardwaremodel => 'x86_64',
      :interfaces => 'lo',
      :ipaddress_lo => '127.0.0.1',
      :operatingsystemmajrelease => '6',
      :operatingsystem => 'RedHat',
      :operatingsystemmajrelease => '6',
      :processorcount => 4,
      :uid_min => '500'
    },
    "RHEL 7" => {
      :fqdn => 'spec.test',
      :grub_version => '0.97',
      :hardwaremodel => 'x86_64',
      :interfaces => 'lo',
      :ipaddress_lo => '127.0.0.1',
      :operatingsystemmajrelease => '7',
      :operatingsystem => 'RedHat',
      :operatingsystemmajrelease => '7',
      :processorcount => 4,
      :uid_min => '500'
    }
  }

  shared_examples_for "a fact set pam" do
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
      if (facts[:operatingsystem] == 'RedHat') && (facts[:operatingsystemmajrelease].to_s < '7')
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
        if (facts[:operatingsystem] == 'RedHat') && (facts[:operatingsystemmajrelease].to_s < '7')
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
        if (facts[:operatingsystem] == 'RedHat') && (facts[:operatingsystemmajrelease].to_s < '7')
          should create_file('/etc/nslcd.conf').with({ :content => /threads 20/ })
          should create_file('/etc/nslcd.conf').without({ :content => /threads 5/ })
        else
          should_not create_file('/etc/nslcd.conf')
        end
      }
    end
  end

  describe "RHEL 6" do
    it_behaves_like "a fact set pam"
    let(:facts) {base_facts['RHEL 6']}
  end

  describe "RHEL 7" do
    it_behaves_like "a fact set pam"
    let(:facts) {base_facts['RHEL 7']}
  end
end
