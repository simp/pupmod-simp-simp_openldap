require 'spec_helper'

describe 'simp_openldap::slapo::syncprov' do
  on_supported_os.each do |os, facts|
    context "on #{os}" do
      let(:facts) do
        facts
      end

      it { is_expected.to create_simp_openldap__server__dynamic_include('syncprov').with_content(
        /syncprov-nopresent FALSE/
      )}

      it { is_expected.to create_simp_openldap__server__limits('Allow Sync User Unlimited').with_limits([
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
            is_expected.to create_simp_openldap__server__dynamic_include('syncprov').with_content(
              /syncprov-checkpoint #{params[:checkpoint]}/
            )
          }.to_not raise_error
        end
      end
    end
  end
end
