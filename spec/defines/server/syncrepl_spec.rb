require 'spec_helper'

describe 'openldap::server::syncrepl' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end

        let(:title) { '111' }

        let(:params) {{ :syncrepl_retry => '3 10' }}

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
    end
  end
end
