require 'spec_helper'

describe 'simp_openldap::server::dynamic_include' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:pre_condition) {
          'class { "simp_openldap": is_server => true }'
        }

        let(:facts) do
          facts
        end

        let(:title) { 'its_a_test' }

        let(:params) {{
          :content => 'foo',
          :order   => 100
        }}

        it { is_expected.to compile.with_all_deps }

        it { is_expected.to create_concat('/etc/openldap/slapd.access') }
        it { is_expected.to create_concat__fragment("openldap_dynamic_include_#{title}").with_content(/#{params[:content]}/) }
      end
    end
  end
end
