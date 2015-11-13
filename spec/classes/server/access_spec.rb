require 'spec_helper'

describe 'openldap::server::access' do
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
      :selinux_current_mode => 'permissive',
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
      :selinux_current_mode => 'permissive',
      :processorcount => 4,
      :uid_min => '500'
    }
  }

  shared_examples_for "a fact set access" do
    it { should create_class('openldap::server') }

    it { should compile.with_all_deps }
    it { should create_concat_build('slapd_access').that_notifies('Exec[postprocess_slapd.access]') }
    it { should create_exec('postprocess_slapd.access').that_requires('File[/usr/local/sbin/simp/build_slapd_access.rb]') }
    it { should create_file('/usr/local/sbin/simp/build_slapd_access.rb') }
    it {
      should create_file('/etc/openldap/slapd.access').with({
        :require => 'Exec[postprocess_slapd.access]',
        :notify  => 'Service[slapd]',
        :source  => /file:\/\/.*slapd.access.out/
      })
    }
  end

  base_facts.keys.sort.each do |os_version|
    describe os_version do
      it_behaves_like "a fact set access"
      let(:facts) {base_facts[os_version]}
    end
  end
end
