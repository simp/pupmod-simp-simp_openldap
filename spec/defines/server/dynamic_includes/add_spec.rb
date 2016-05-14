require 'spec_helper'

describe 'openldap::server::dynamic_includes::add' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end

        let(:title) { 'its_a_test' }

        let(:params) {{
          :content => 'foo',
          :order   => '100'
        }}

        it { should compile.with_all_deps }

        it { should create_concat_fragment("slapd_dynamic_includes+#{params[:order]}_#{title}.inc").with_content(/#{params[:content]}/) }
      end
    end
  end
end
