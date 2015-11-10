require 'spec_helper'

describe 'openldap::server::conf' do
  let :pre_condition do
    'include ::openldap'
  end

  base_facts = {
    "RHEL 6" => {
      :fqdn => 'spec.test',
      :grub_version => '0.97',
      :hardwaremodel => 'x86_64',
      :interfaces => 'lo',
      :ipaddress_lo => '127.0.0.1',
      :lsbmajdistrelease => '6',
      :operatingsystem => 'RedHat',
      :operatingsystemmajrelease => '6',
      :processorcount => 4,
      :selinux_current_mode => 'permissive',
      :uid_min => '500'
    },
    "RHEL 7" => {
      :fqdn => 'spec.test',
      :grub_version => '0.97',
      :hardwaremodel => 'x86_64',
      :interfaces => 'lo',
      :ipaddress_lo => '127.0.0.1',
      :lsbmajdistrelease => '7',
      :operatingsystem => 'RedHat',
      :operatingsystemmajrelease => '7',
      :processorcount => 4,
      :selinux_current_mode => 'permissive',
      :uid_min => '500'
    }
  }

  let(:params){{
    :suffix       => 'dc=host,dc=net',
    :authz_regexp => [{
      'match'   => '^uid=([^,]+),.*',
      'replace' => "uid=\$1,ou=People,dc=host,dc=net"
    }]
  }}

  # This sets up the tests that should *always* work.
  shared_examples 'a fact set conf' do
    it { should create_class('openldap::server') }

    it { should compile.with_all_deps }
    it { should create_file('/etc/openldap/DB_CONFIG').with_content(/set_data_dir/) }
    it { should create_file('/etc/openldap/default.ldif').with_content(/dn: #{params[:suffix]}/) }
    it { should create_file('/etc/openldap/default.ldif').with_content(/pwdCheckModule: .*simp_check_password.so/) }
    it {
      if ['RedHat','CentOS'].include?(facts[:operatingsystem]) and facts[:operatingsystemmajrelease] < "7"
      then
        should create_file('/etc/sysconfig/ldap').with_content(/SLAPD_OPTIONS.*slapd.conf/)
      else
        should create_file('/etc/sysconfig/slapd').with_content(/SLAPD_URLS.*ldap.*:\/\//)
      end
    }
  end

  base_facts.keys.sort.each do |os_version|
    let(:facts){base_facts[os_version]}

    it_behaves_like "a fact set conf"

    context 'with_tls' do
      it_behaves_like "a fact set conf"

      it { should create_pki__copy('/etc/openldap').that_notifies('Service[slapd]') }
      it { should create_file('/etc/openldap/slapd.conf').with({
          :notify => 'Service[slapd]',
          :content => /TLSCertificateFile/
        })
      }
    end

    context 'without_tls' do
      let(:params){{
        :suffix       => 'dc=host,dc=net',
        :authz_regexp => [{
          'match'   => '^uid=([^,]+),.*',
          'replace' => "uid=\$1,ou=People,dc=host,dc=net"
        }],
        :use_tls      => false
      }}

      it_behaves_like "a fact set conf"

      it { should_not create_pki__copy('/etc/openldap') }
      it { should create_file('/etc/openldap/slapd.conf').with_notify('Service[slapd]') }
      it { should create_file('/etc/openldap/slapd.conf').without_content(/TLSCertificateFile/) }
    end

    context 'x86_64' do
      it_behaves_like "a fact set conf"

      ['/usr/lib64/openldap','/usr/lib/openldap'].each do |file|
        it { should create_file(file).with_recurse(true) }
      end
    end

    context 'i386' do
      facts = base_facts[os_version].dup
      facts[:hardwaremodel] = description
      let(:facts){facts}

      it_behaves_like "a fact set conf"

      it { should create_file('/usr/lib/openldap').with_recurse(true) }
    end

    context 'force_log_quick_kill' do
      let(:params){{
        :suffix       => 'dc=host,dc=net',
        :authz_regexp => [{
          'match'   => '^uid=([^,]+),.*',
          'replace' => "uid=\$1,ou=People,dc=host,dc=net"
        }],
        :force_log_quick_kill => true
      }}

      it_behaves_like "a fact set conf"

      it { should create_simplib__incron__add_system_table('nuke_openldap_log_files').with_command('/bin/rm $@/$#') }
    end

    context 'enable_iptables' do
      let(:params) {{ :enable_iptables => true }}

      it_behaves_like "a fact set conf"

      it { should create_class('iptables') }
      it { should create_iptables__add_tcp_stateful_listen('allow_ldap').with_dports('ldap') }
      it { should create_iptables__add_tcp_stateful_listen('allow_ldaps').with_dports('ldaps') }
    end

    context 'do_not_use_iptables' do
      let(:params){{
        :suffix       => 'dc=host,dc=net',
        :authz_regexp => [{
          'match'   => '^uid=([^,]+),.*',
          'replace' => "uid=\$1,ou=People,dc=host,dc=net"
        }],
        :enable_iptables => false
      }}

      it_behaves_like "a fact set conf"

      it { should_not create_iptables__add_tcp_stateful_listen('allow_ldap') }
      it { should_not create_iptables__add_tcp_stateful_listen('allow_ldaps') }
    end

    context 'use_iptables_no_listen_ldaps' do
      let(:params){{
        :suffix       => 'dc=host,dc=net',
        :authz_regexp => [{
          'match'   => '^uid=([^,]+),.*',
          'replace' => "uid=\$1,ou=People,dc=host,dc=net"
        }],
        :listen_ldaps => false,
        :enable_iptables => true
      }}

      it_behaves_like "a fact set conf"

      it { should create_class('iptables') }
      it { should create_iptables__add_tcp_stateful_listen('allow_ldap').with_dports('ldap') }
      it { should_not create_iptables__add_tcp_stateful_listen('allow_ldaps') }
    end

    context 'use_iptables_no_listen_ldap_or_ldaps' do
      let(:params){{
        :suffix       => 'dc=host,dc=net',
        :authz_regexp => [{
          'match'   => '^uid=([^,]+),.*',
          'replace' => "uid=\$1,ou=People,dc=host,dc=net"
        }],
        :listen_ldap  => false,
        :listen_ldaps => false,
        :enable_iptables => true
      }}

      it_behaves_like "a fact set conf"

      it { should create_class('iptables') }
      it { should_not create_iptables__add_tcp_stateful_listen('allow_ldap') }
      it { should_not create_iptables__add_tcp_stateful_listen('allow_ldaps') }
    end

    context 'audit_transactions' do
      let(:params){{
        :auditlog           => '/var/log/ldap_audit.log',
        :auditlog_rotate    => 'daily',
        :auditlog_preserve  => '7',
        :suffix             => 'dc=host,dc=net',
        :authz_regexp       => [{
          'match'   => '^uid=([^,]+),.*',
          'replace' => "uid=\$1,ou=People,dc=host,dc=net"
        }],
        :enable_logging => true
      }}

      it_behaves_like "a fact set conf"

      it { should create_class('logrotate') }
      it { should create_class('rsyslog') }

      it { should create_file(params[:auditlog]) }
      it { should create_logrotate__add('slapd_audit_log').with({
          :log_files      => params[:auditlog],
          :create         => '0640 ldap ldap',
          :rotate_period  => params[:auditlog_rotate],
          :rotate         => params[:auditlog_preserve]
        })
      }
      it { should create_openldap__server__dynamic_includes__add('auditlog').with_content(/auditlog #{params[:auditlog]}/) }
      it { should create_rsyslog__rule__data_source('openldap_audit').with_rule(/File="#{params[:auditlog]}"/) }
      it { should create_rsyslog__rule__drop('1_drop_openldap_passwords').with_rule(/contains\s+'Password::\s+'/) }
    end

    context 'audit_transactions_no_audit_to_syslog' do
      let(:params){{
        :auditlog           => '/var/log/ldap_audit.log',
        :auditlog_rotate    => 'daily',
        :auditlog_preserve  => '7',
        :audit_to_syslog    => false,
        :suffix             => 'dc=host,dc=net',
        :authz_regexp       => [{
          'match'   => '^uid=([^,]+),.*',
          'replace' => "uid=\$1,ou=People,dc=host,dc=net"
        }],
        :enable_logging     => true
      }}

      it_behaves_like "a fact set conf"

      it { should create_class('logrotate') }

      it { should create_file(params[:auditlog]) }
      it { should create_logrotate__add('slapd_audit_log').with({
          :log_files      => params[:auditlog],
          :create         => '0640 ldap ldap',
          :rotate_period  => params[:auditlog_rotate],
          :rotate         => params[:auditlog_preserve]
        })
      }
      it { should create_openldap__server__dynamic_includes__add('auditlog').with_content(/auditlog #{params[:auditlog]}/) }
      it { should_not create_rsyslog__add_conf('openldap_audit') }
      it { should_not create_rsyslog__rule__drop('1_drop_openldap_passwords') }
    end

    context 'logging_enabled' do
      let(:params){{
        :suffix             => 'dc=host,dc=net',
        :authz_regexp       => [{
          'match'   => '^uid=([^,]+),.*',
          'replace' => "uid=\$1,ou=People,dc=host,dc=net"
        }],
        :enable_logging     => true,
        :log_to_file        => true,
        :log_file           => '/foo/bar'
      }}
      it_behaves_like "a fact set conf"

      it { should create_class('logrotate') }
      it { should create_class('rsyslog') }

      it { should create_rsyslog__rule__local('05_openldap_local').with_rule(/local4\.\*/) }
      it { should create_logrotate__add('slapd').with({
          :log_files => [params[:log_file]]
        })
      }
    end

    context 'logging_disabled' do
      it_behaves_like "a fact set conf"

      it { should_not create_rsyslog__rule__local('05_openldap_local') }
      it { should_not create_logrotate__add('slapd') }
    end

    context 'threads_is_dynamic' do
      let(:params){{
        :suffix       => 'dc=host,dc=net',
        :authz_regexp => [{
          'match'   => '^uid=([^,]+),.*',
          'replace' => "uid=\$1,ou=People,dc=host,dc=net"
        }],
      }}

      it_behaves_like "a fact set conf"

      it { should create_file('/etc/openldap/slapd.conf').with_content(/threads   16/) }
      it { should create_file('/etc/openldap/slapd.conf').without_content(/threads   8/) }
    end

    context 'threads_is_user_overridden' do
      let(:params){{
        :suffix       => 'dc=host,dc=net',
        :authz_regexp => [{
          'match'   => '^uid=([^,]+),.*',
          'replace' => "uid=\$1,ou=People,dc=host,dc=net"
        }],
        :threads => 20
      }}

      it_behaves_like "a fact set conf"

      it { should create_file('/etc/openldap/slapd.conf').with_content(/threads   20/) }
      it { should create_file('/etc/openldap/slapd.conf').without_content(/threads   8/) }
      it { should create_file('/etc/openldap/slapd.conf').without_content(/threads   16/) }
    end
  end
end
