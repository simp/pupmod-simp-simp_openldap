require 'spec_helper'

describe 'simp_openldap::server' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end

        it { is_expected.to create_class('simp_openldap') }
        it { is_expected.to create_class('simp_openldap::server::conf') }

        it { is_expected.to compile.with_all_deps }
        it {
          is_expected.to create_exec('bootstrap_ldap')
          is_expected.to create_exec('bootstrap_ldap').that_comes_before('Exec[fixperms]')
        }
        it { is_expected.to create_exec('fixperms').that_notifies('Service[slapd]') }
        it {
          is_expected.to create_exec('fix_bad_upgrade').with({
            :before => [
              'Exec[bootstrap_ldap]',
              'File[/etc/openldap/slapd.conf]',
            ],
            :notify => 'File[/var/lib/ldap/DB_CONFIG]'
          })
        }

        [
          '/etc/openldap',
          '/var/lib/ldap/DB_CONFIG',
          '/var/lib/ldap',
          '/var/lib/ldap/db',
          '/var/lib/ldap/logs',
          '/var/log/slapd.log'
        ].each do |file|
          it {
            is_expected.to create_file(file).that_requires("Class[Simp_openldap::Server::Install]")
          }
        end

        it { is_expected.to create_file('/usr/local/sbin/ldap_bootstrap_check.sh').with({
            :require => [
              'File[/var/lib/ldap/DB_CONFIG]',
              'File[/var/lib/ldap/db]',
              'File[/var/lib/ldap/logs]',
              'File[/etc/openldap/slapd.conf]',
              'File[/etc/openldap/default.ldif]',
              'File[/etc/openldap/schema]'
            ]
          })
        }

        it { is_expected.to create_group('ldap').that_requires("Class[Simp_openldap::Server::Install]") }

        it { is_expected.to create_package('openldap') }
        it { is_expected.to create_package("openldap-servers.#{facts[:hardwaremodel]}") }

        it { is_expected.to create_user('ldap').with({
            :require  => "Class[Simp_openldap::Server::Install]",
            :notify   => 'Class[Simp_openldap::Server::Service]'
          })
        }

        it { is_expected.to create_class('simp_openldap::slapo::syncprov') }
        it { is_expected.to create_class('simp_openldap::slapo::ppolicy') }
        it { is_expected.to_not create_tcpwrappers__allow('slapd').with_pattern('ALL') }
        it { is_expected.to create_file('/etc/openldap/schema') }

        context 'no_sync' do
          let(:params){{ :allow_sync => false }}

          it { is_expected.to_not create_class('simp_openldap::slapo::syncprov') }
        end

        context 'no_ppolicy' do
          let(:params){{ :use_ppolicy => false }}

          it { is_expected.to_not create_class('simp_openldap::slapo::ppolicy') }
        end

        context 'no_tcpwrappers' do
          let(:params){{ :tcpwrappers => true }}

          it { is_expected.to create_tcpwrappers__allow('slapd').with_pattern('ALL') }
        end
      end
    end
  end
end
