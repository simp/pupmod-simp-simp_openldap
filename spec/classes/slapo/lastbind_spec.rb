require 'spec_helper'

describe 'openldap::slapo::lastbind' do
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

  shared_examples_for "a fact set lastbind" do
    let(:params) {{ :lastbind_precision => '3600' }}

    it { should create_class('openldap::server::dynamic_includes') }

    it { should create_file('/etc/openldap/lastbind.conf').with_content(
      "lastbind-precision #{params[:lastbind_precision]}\n"
    )}

    it { should create_openldap__server__dynamic_includes__add('lastbind').that_requires(
      'Package[simp-lastbind]'
    )}

    it { should create_package('simp-lastbind') }

   end
  describe "RHEL 6" do
    it_behaves_like "a fact set lastbind"
    let(:facts) {base_facts['RHEL 6']}
  end

  describe "RHEL 7" do
    it_behaves_like "a fact set lastbind"
    let(:facts) {base_facts['RHEL 7']}
  end
end
