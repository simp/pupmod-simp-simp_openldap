require 'spec_helper'

describe 'openldap::server::access::add' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end

        let(:title) { 'its_a_test' }

        let(:params) {{
          :what  => 'on_second',
          :who   => 'on_first',
          :order => '50'
        }}

        it { should compile.with_all_deps }

        it {
          should create_simpcat_fragment("slapd_access+#{params[:order]}_#{title}.inc").with_content(
            /Who: #{params[:who]}/
          )
          should create_simpcat_fragment("slapd_access+#{params[:order]}_#{title}.inc").with_content(
            /What: #{params[:what]}/
          )
        }

        context 'no_who_no_content' do
          let(:params) {{
            :what     => 'on_second',
            :who      => '',
            :content  => ''
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

