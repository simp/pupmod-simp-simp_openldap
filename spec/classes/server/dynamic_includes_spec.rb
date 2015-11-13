require 'spec_helper'

describe 'openldap::server::dynamic_includes' do
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
      :selinux_current_mode => 'permissive',
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
      :selinux_current_mode => 'permissive',
      :uid_min => '500'
    }
  }

  shared_examples_for "a fact set dynamic_includes" do
    it { should create_concat_build('slapd_dynamic_includes').with({
        :target => '/etc/openldap/dynamic_includes',
        :before => 'Exec[bootstrap_ldap]'
      })
    }
  end

  describe "RHEL 6" do
    it_behaves_like "a fact set dynamic_includes"
    let(:facts) {base_facts['RHEL 6']}
  end

  describe "RHEL 7" do
    it_behaves_like "a fact set dynamic_includes"
    let(:facts) {base_facts['RHEL 7']}
  end
end
