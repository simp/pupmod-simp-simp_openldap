require 'spec_helper'

describe 'openldap::server::add_limits' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end

        let(:title) { '111' }

        let(:params) {{
          :who => 'on_first',
          :limits => ['foo','bar','baz']
        }}

        it { should create_class('openldap::server::dynamic_includes') }

        it { should compile.with_all_deps }

        it { should create_openldap__server__dynamic_includes__add("limit_#{title}").with_content(
          /limits #{params[:who]} #{params[:limits].join(' ')}/
        )}
      end
    end
  end
end
