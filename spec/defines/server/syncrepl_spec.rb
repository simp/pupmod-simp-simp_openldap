require 'spec_helper'

describe 'openldap::server::syncrepl' do
  let(:title) { '111' }

  let(:params) {{ :syncrepl_retry => '3 10' }}

  base_facts = {
    "RHEL 6" => {
      :fqdn => 'spec.test',
      :grub_version => '0.97',
      :hardwaremodel => 'x86_64',
      :interfaces => 'lo',
      :ipaddress_lo => '127.0.0.1',
      :lsbdistrelease => '6.6',
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
      :lsbdistrelease => '7.0',
      :lsbmajdistrelease => '7',
      :operatingsystem => 'RedHat',
      :operatingsystemmajrelease => '7',
      :processorcount => 4,
      :uid_min => '500'
    }
  }

  shared_examples_for "a fact set syncrepl" do
    it { should create_class('openldap::server::dynamic_includes') }

    it { should compile.with_all_deps }

    it {
      should create_openldap__server__dynamic_includes__add('syncrepl').with_content(
        /syncrepl rid=#{params[:rid]}/
      )
      should create_openldap__server__dynamic_includes__add('syncrepl').with_content(
        /retry="#{params[:syncrepl_retry]}"/
      )
    }

    context 'syncrepl_retry_bad' do
      let(:params) {{ :syncrepl_retry => '3 10 3' }}

      it do
        expect {
          should compile.with_all_deps
        }.to raise_error(/" 3" does not match/)
      end
    end
  end

  describe "RHEL 6" do
    it_behaves_like "a fact set syncrepl"
    let(:facts) {base_facts['RHEL 6']}
  end

  describe "RHEL 7" do
    it_behaves_like "a fact set syncrepl"
    let(:facts) {base_facts['RHEL 7']}
  end
end
