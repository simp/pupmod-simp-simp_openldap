require 'spec_helper'

describe 'openldap::slapo::ppolicy' do
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

  shared_examples_for "a fact set ppolicy" do
    let(:params) {{
      :suffix       => 'dn=host,dn=net',
      :use_cracklib => true
    }}

    it { should create_class('openldap::server::dynamic_includes') }

    it { should create_package('simp-ppolicy-check-password') }

    it { should create_openldap__server__dynamic_includes__add('ppolicy').with_content(
      /ppolicy_default\s+"cn=default,ou=pwpolicies,#{params[:suffix]}"/
    )}

    it {
      if ['RedHat','CentOS'].include?(facts[:operatingsystem]) and facts[:operatingsystemmajrelease] < "7"
        conf_name = 'check_password.conf'
      else
        conf_name = 'simp_check_password.conf'
      end

      should create_file("/etc/openldap/#{conf_name}").with({
        :group    => 'ldap',
        :mode     => '0640',
        :content  => /use_cracklib 1/
      })
    }
  end

  describe "RHEL 6" do
    it_behaves_like "a fact set ppolicy"
    let(:facts) {base_facts['RHEL 6']}
  end

  describe "RHEL 7" do
    it_behaves_like "a fact set ppolicy"
    let(:facts) {base_facts['RHEL 7']}
  end
end
