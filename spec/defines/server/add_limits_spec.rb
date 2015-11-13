require 'spec_helper'

describe 'openldap::server::add_limits' do
  let(:title) { '111' }

  let(:params) {{
    :who => 'on_first',
    :limits => ['foo','bar','baz']
  }}

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

  shared_examples_for "a fact set add_limits" do
    it { should create_class('openldap::server::dynamic_includes') }

    it { should compile.with_all_deps }

    it { should create_openldap__server__dynamic_includes__add("limit_#{title}").with_content(
      /limits #{params[:who]} #{params[:limits].join(' ')}/
    )}
  end

  describe "RHEL 6" do
    it_behaves_like "a fact set add_limits"
    let(:facts) {base_facts['RHEL 6']}
  end

  describe "RHEL 7" do
    it_behaves_like "a fact set add_limits"
    let(:facts) {base_facts['RHEL 7']}
  end
end
