require 'spec_helper'

describe 'simp_openldap::server::syncrepl' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:pre_condition) {
          'class { "simp_openldap": is_server => true }'
        }

        let(:facts) do
          facts
        end

        let(:title) { '111' }

        let(:params) {{ :syncrepl_retry => '3 10' }}

        it { is_expected.to compile.with_all_deps }

        it {
          is_expected.to create_simp_openldap__server__dynamic_include('syncrepl').with_content(
            /syncrepl rid=#{params[:rid]}/
          )
          is_expected.to create_simp_openldap__server__dynamic_include('syncrepl').with_content(
            /retry="#{params[:syncrepl_retry]}"/
          )
        }

        context 'syncrepl_retry_bad' do
          let(:params) {{ :syncrepl_retry => '3 10 3' }}

          it do
            expect {
              is_expected.to compile.with_all_deps
            }.to raise_error(/" 3" does not match/)
          end
        end
      end
    end
  end
end
