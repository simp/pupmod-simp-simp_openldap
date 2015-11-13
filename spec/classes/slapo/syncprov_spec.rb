require 'spec_helper'

describe 'openldap::slapo::syncprov' do
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

  shared_examples_for "a fact set syncprov" do
    it { should create_class('openldap::server::dynamic_includes') }

    it { should create_openldap__server__dynamic_includes__add('syncprov').with_content(
      /syncprov-nopresent FALSE/
    )}

    it { should create_openldap__server__add_limits('Allow Sync User Unlimited').with_limits([
        'size.soft=unlimited',
        'size.hard=unlimited',
        'time.soft=unlimited',
        'time.hard=unlimited'
      ])
    }

    context 'validate_checkpoint' do
      let(:params) {{ :checkpoint => '2 4' }}

      it do
        expect {
          should create_openldap__server__dynamic_includes__add('syncprov').with_content(
            /syncprov-checkpoint #{params[:checkpoint]}/
          )
        }.to_not raise_error
      end
    end

    context 'validate_checkpoint_bad' do
      let(:params) {{ :checkpoint => '2' }}

      it do
        expect {
          should create_openldap__server__dynamic_includes__add('syncprov').with_content(
            /syncprov-checkpoint #{params[:checkpoint]}/
          )
        }.to raise_error(/"#{params[:checkpoint]}" does not match/)
      end
    end
  end

  describe "RHEL 6" do
    it_behaves_like "a fact set syncprov"
    let(:facts) {base_facts['RHEL 6']}
  end

  describe "RHEL 7" do
    it_behaves_like "a fact set syncprov"
    let(:facts) {base_facts['RHEL 7']}
  end
end
