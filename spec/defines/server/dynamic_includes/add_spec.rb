require 'spec_helper'

describe 'openldap::server::dynamic_includes::add' do
  let(:title) { 'its_a_test' }

  let(:params) {{
    :content => 'foo',
    :order   => '100'
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

  shared_examples_for "a fact set dynamic_add" do
    it { should compile.with_all_deps }

    it { should create_concat_fragment("slapd_dynamic_includes+#{params[:order]}_#{title}.inc").with_content(/#{params[:content]}/) }
  end

  describe "RHEL 6" do
    it_behaves_like "a fact set dynamic_add"
    let(:facts) {base_facts['RHEL 6']}
  end

  describe "RHEL 7" do
    it_behaves_like "a fact set dynamic_add"
    let(:facts) {base_facts['RHEL 7']}
  end
end
