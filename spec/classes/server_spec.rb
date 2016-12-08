require 'spec_helper'

describe 'openldap::server' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end

        it { is_expected.to create_class('openldap') }
        it { is_expected.to create_class('openldap::server::conf') }
        it { is_expected.to create_class('openldap::server::access') }
        it { is_expected.to create_class('openldap::server::dynamic_includes') }

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
            is_expected.to create_file(file).that_requires("Package[openldap-servers.#{facts[:hardwaremodel]}]")
          }
        end

        it { is_expected.to create_file('/etc/openldap/dynamic_includes').with({
            :require    => "Package[openldap-servers.#{facts[:hardwaremodel]}]",
            :subscribe  => 'Simpcat_build[slapd_dynamic_includes]'
          })
        }

        it { is_expected.to create_file('/usr/local/sbin/ldap_bootstrap_check.sh').with({
            :require => [
              'File[/var/lib/ldap/DB_CONFIG]',
              'File[/var/lib/ldap/db]',
              'File[/var/lib/ldap/logs]',
              'File[/etc/openldap/slapd.conf]',
              'File[/etc/openldap/slapd.access]',
              'File[/etc/openldap/default.ldif]',
              'File[/etc/openldap/dynamic_includes]',
              'File[/etc/openldap/schema]'
            ]
          })
        }

        it { is_expected.to create_group('ldap').that_requires("Package[openldap-servers.#{facts[:hardwaremodel]}]") }

        it { is_expected.to create_package('openldap') }
        it { is_expected.to create_package("openldap-servers.#{facts[:hardwaremodel]}") }

        it { is_expected.to create_service('slapd').with({
            :require    => [
              "Package[openldap-servers.#{facts[:hardwaremodel]}]",
              "Class[Openldap::Server::Fix_bad_upgrade]"
            ]
          })
        }

        it { is_expected.to create_user('ldap').with({
            :require  => "Package[openldap-servers.#{facts[:hardwaremodel]}]",
            :notify   => 'Class[Openldap::Server::Service]'
          })
        }

        it { is_expected.to create_class('openldap::slapo::syncprov') }
        it { is_expected.to create_class('openldap::slapo::ppolicy') }
        it { is_expected.to_not create_tcpwrappers__allow('slapd').with_pattern('ALL') }
        it { is_expected.to create_file('/etc/openldap/schema') }

        context 'no_sync' do
          let(:params){{ :allow_sync => false }}

          it { is_expected.to_not create_class('openldap::slapo::syncprov') }
        end

        context 'no_ppolicy' do
          let(:params){{ :use_ppolicy => false }}

          it { is_expected.to_not create_class('openldap::slapo::ppolicy') }
        end

        context 'no_tcpwrappers' do
          let(:params){{ :use_tcpwrappers => true }}

          it { is_expected.to create_tcpwrappers__allow('slapd').with_pattern('ALL') }
        end
      end
    end
  end
end
