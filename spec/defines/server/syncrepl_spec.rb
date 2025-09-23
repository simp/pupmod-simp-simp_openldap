require 'spec_helper'

describe 'simp_openldap::server::syncrepl' do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:pre_condition) do
          'class { "simp_openldap": is_server => true }'
        end
        let(:title) { '111' }
        let(:params) { { syncrepl_retry: '3 10' } }

        let(:facts) do
          os_facts
        end

        if os_facts.dig(:os, :release, :major) >= '8'
          it { skip("does not support #{os}") }
          next
        end

        it { is_expected.to compile.with_all_deps }

        it {
          is_expected.to create_simp_openldap__server__dynamic_include('syncrepl').with_content(
            %r{syncrepl rid=#{params[:rid]}},
          )
          is_expected.to create_simp_openldap__server__dynamic_include('syncrepl').with_content(
            %r{retry="#{params[:syncrepl_retry]}"},
          )
        }

        context 'syncrepl_retry_bad' do
          let(:params) { { syncrepl_retry: '3 10 3' } }

          it do
            expect {
              is_expected.to compile.with_all_deps
            }.to raise_error(%r{" 3" does not match})
          end
        end
      end
    end
  end
end
