require 'spec_helper'

describe 'openldap::slapo::syncprov' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end

        it { is_expected.to create_class('openldap::server::dynamic_includes') }

        it { is_expected.to create_openldap__server__dynamic_includes__add('syncprov').with_content(
          /syncprov-nopresent FALSE/
        )}

        it { is_expected.to create_openldap__server__add_limits('Allow Sync User Unlimited').with_limits([
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
              is_expected.to create_openldap__server__dynamic_includes__add('syncprov').with_content(
                /syncprov-checkpoint #{params[:checkpoint]}/
              )
            }.to_not raise_error
          end
        end

        context 'validate_checkpoint_bad' do
          let(:params) {{ :checkpoint => '2' }}

          it { expect { is_expected.to compile }.to raise_error }
        end
      end
    end
  end
end
