require 'spec_helper'

describe 'simp_openldap::server::access' do
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
          :what  => 'on_second',
          :who   => 'on_first',
          :order => 50
        }}

        it { is_expected.to compile.with_all_deps }

        it { is_expected.to create_concat('/etc/openldap/slapd.access') }

        it {
          is_expected.to create_concat__fragment("openldap_access_#{title}").with_content(
            %r{(?m)access to #{params[:what]}\s+by #{params[:who]}}
          )
        }

        context 'no_who_no_content' do
          let(:params) {{
            :what     => 'on_second'
          }}

          it do
            expect {
              should compile.with_all_deps
            }.to raise_error(/You must specify "\$who" if you are not specifying "\$content"/)
          end
        end
      end
    end
  end
end
