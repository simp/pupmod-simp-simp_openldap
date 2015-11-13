require 'spec_helper'

describe 'openldap::server' do
  base_facts = {
    "RHEL 6" => {
      :fqdn => 'spec.test',
      :grub_version => '0.97',
      :hardwaremodel => 'x86_64',
      :interfaces => 'lo',
      :ipaddress_lo => '127.0.0.1',
      :operatingsystemmajrelease => '6',
      :operatingsystem => 'RedHat',
      :operatingsystemmajrelease => '6',
      :selinux_current_mode => 'permissive',
      :processorcount => 4,
      :uid_min => '500'
    },
    "RHEL 7" => {
      :fqdn => 'spec.test',
      :grub_version => '0.97',
      :hardwaremodel => 'x86_64',
      :interfaces => 'lo',
      :ipaddress_lo => '127.0.0.1',
      :operatingsystemmajrelease => '7',
      :operatingsystem => 'RedHat',
      :operatingsystemmajrelease => '7',
      :selinux_current_mode => 'permissive',
      :processorcount => 4,
      :uid_min => '500'
    }
  }

  # This sets up the tests that should *always* work.
  shared_examples 'a fact set server' do
    it { should create_class('openldap') }
    it { should create_class('openldap::server::conf') }
    it { should create_class('openldap::server::access') }
    it { should create_class('openldap::server::dynamic_includes') }

    it { should compile.with_all_deps }
    it {
      should create_exec('bootstrap_ldap').that_notifies('Service[slapd]')
      should create_exec('bootstrap_ldap').that_comes_before('Exec[fixperms]')
    }
    it { should create_exec('fixperms').that_notifies('Service[slapd]') }
    it {
      should create_exec('fix_bad_upgrade').with({
        :before => [
          'Exec[bootstrap_ldap]',
          'File[/etc/openldap/slapd.conf]',
        ],
        :notify => [
          'File[/var/lib/ldap/DB_CONFIG]',
          'Service[slapd]'
        ]
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
        should create_file(file).that_requires("Package[openldap-servers.#{facts[:hardwaremodel]}]")
      }
    end

    it { should create_file('/etc/openldap/dynamic_includes').with({
        :require    => "Package[openldap-servers.#{facts[:hardwaremodel]}]",
        :subscribe  => 'Concat_build[slapd_dynamic_includes]'
      })
    }

    it { should create_file('/usr/local/sbin/ldap_bootstrap_check.sh').with({
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

    it { should create_group('ldap').that_requires("Package[openldap-servers.#{facts[:hardwaremodel]}]") }

    it { should create_package('openldap') }
    it { should create_package("openldap-servers.#{facts[:hardwaremodel]}") }

    it { should create_service('slapd').with({
        :require    => "Package[openldap-servers.#{facts[:hardwaremodel]}]"
      })
    }

    it { should create_user('ldap').with({
        :require  => "Package[openldap-servers.#{facts[:hardwaremodel]}]",
        :notify   => 'Service[slapd]'
      })
    }
  end

  base_facts.keys.sort.each do |os_version|
    let(:facts) {base_facts[os_version]}

    it_behaves_like "a fact set server"
    it { should create_class('openldap::slapo::syncprov') }
    it { should create_class('openldap::slapo::ppolicy') }
    it { should create_tcpwrappers__allow('slapd').with_pattern('ALL') }
    it { should create_file('/etc/openldap/schema') }

    context 'no_sync' do
      let(:params){{ :allow_sync => false }}

      it_behaves_like "a fact set server"
      it { should_not create_class('openldap::slapo::syncprov') }
    end

    context 'no_ppolicy' do
      let(:params){{ :use_ppolicy => false }}

      it_behaves_like "a fact set server"
      it { should_not create_class('openldap::slapo::ppolicy') }
    end

    context 'no_tcpwrappers' do
      let(:params){{ :use_tcpwrappers => false }}

      it_behaves_like "a fact set server"
      it { should_not create_tcpwrappers__allow('slapd').with_pattern('ALL') }
    end
  end
end
