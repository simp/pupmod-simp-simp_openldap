require 'spec_helper'

describe 'simp_openldap::server::limits' do
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

        let(:params) {{
          :who => 'on_first',
          :limits => ['foo','bar','baz']
        }}

        it { is_expected.to compile.with_all_deps }

        it { is_expected.to create_simp_openldap__server__dynamic_include("limit_#{title}").with_content(
          /limits #{params[:who]} #{params[:limits].join(' ')}/
        )}
      end
    end
  end
end
