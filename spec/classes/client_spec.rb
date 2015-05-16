require 'spec_helper'

describe 'openldap::client' do
  base_facts = {
    "RHEL 6" => {
      :fqdn => 'spec.test',
      :grub_version => '0.97',
      :hardwaremodel => 'x86_64',
      :interfaces => 'lo',
      :ipaddress_lo => '127.0.0.1',
      :lsbmajdistrelease => '6',
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
      :lsbmajdistrelease => '7',
      :operatingsystem => 'RedHat',
      :operatingsystemmajrelease => '7',
      :processorcount => 4,
      :uid_min => '500'
    }
  }

  shared_examples_for "a fact set client" do
    it { should create_class('openldap') }
    it { should create_class('openldap::client') }

    it { should compile.with_all_deps }
    it { should create_file('/etc/openldap/ldap.conf').with_content(/TLS_CIPHER_SUITE\s+HIGH:-SSLv2/) }
    it { should create_file('/root/.ldaprc') }
  end

  describe "RHEL 6" do
    it_behaves_like "a fact set client"
    let(:facts) {base_facts['RHEL 6']}
  end

  describe "RHEL 7" do
    it_behaves_like "a fact set client"
    let(:facts) {base_facts['RHEL 7']}
  end
end
