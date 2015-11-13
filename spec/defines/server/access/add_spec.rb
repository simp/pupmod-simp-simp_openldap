require 'spec_helper'

describe 'openldap::server::access::add' do
  let(:title) { 'its_a_test' }

  let(:params) {{
    :what  => 'on_second',
    :who   => 'on_first',
    :order => '50'
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

  shared_examples_for "a fact set access add" do
    it { should compile.with_all_deps }

    it {
      should create_concat_fragment("slapd_access+#{params[:order]}_#{title}.inc").with_content(
        /Who: #{params[:who]}/
      )
      should create_concat_fragment("slapd_access+#{params[:order]}_#{title}.inc").with_content(
        /What: #{params[:what]}/
      )
    }

    context 'no_who_no_content' do
      let(:params) {{
        :what     => 'on_second',
        :who      => '',
        :content  => ''
      }}

      it do
        expect {
          should compile.with_all_deps
        }.to raise_error(/You must specify "\$who" if you are not specifying "\$content"/)
      end
    end
  end

  describe "RHEL 6" do
    it_behaves_like "a fact set access add"
    let(:facts) {base_facts['RHEL 6']}
  end

  describe "RHEL 7" do
    it_behaves_like "a fact set access add"
    let(:facts) {base_facts['RHEL 7']}
  end
end
