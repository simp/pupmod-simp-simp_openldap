require 'spec_helper'

describe 'simp_openldap' do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts) do
          os_facts
        end

        it { is_expected.to create_class('simp_openldap') }
        it { is_expected.to compile.with_all_deps }

        context 'is_server' do
          let(:params) {{
            :is_server => true
          }}

          if os_facts.dig(:os,:release,:major) >= '8'
            it { skip("does not support #{os}") }
            next
          end

          it { is_expected.to create_class('simp_openldap::server') }
        end
      end
    end
  end
end
