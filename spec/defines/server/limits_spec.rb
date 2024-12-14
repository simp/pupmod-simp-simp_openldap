require 'spec_helper'

describe 'simp_openldap::server::limits' do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:pre_condition) do
          'class { "simp_openldap": is_server => true }'
        end
        let(:title) { '111' }
        let(:params) do
          {
            who: 'on_first',
         limits: ['foo', 'bar', 'baz']
          }
        end

        let(:facts) do
          os_facts
        end

        if os_facts.dig(:os, :release, :major) >= '8'
          it { skip("does not support #{os}") }
          next
        end

        it { is_expected.to compile.with_all_deps }

        it {
          is_expected.to create_simp_openldap__server__dynamic_include("limit_#{title}").with_content(
          %r{limits #{params[:who]} #{params[:limits].join(' ')}},
        )
        }
      end
    end
  end
end
