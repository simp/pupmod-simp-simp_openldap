require 'spec_helper'

describe 'openldap::server::conf' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts[:server_facts] = {
            :servername => facts[:fqdn],
            :serverip   => facts[:ipaddress]
          }
          facts
        end

        let(:pre_condition) {
          %(
            class { "::openldap":
              base_dn   => "dc=host,dc=net",
              is_server => true
            }
          )
        }

        it { is_expected.to create_class('openldap::server') }
        it { is_expected.to create_class('openldap::server::conf::default_ldif') }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to create_file('/etc/openldap/DB_CONFIG').with_content(/set_data_dir/) }
        it { is_expected.to create_file('/etc/openldap/default.ldif').with_content(/dn: dc=host,dc=net/) }
        it { is_expected.to create_file('/etc/openldap/default.ldif').with_content(/pwdCheckModule: .*check_password.so/) }
        it {
          if ['RedHat','CentOS'].include?(facts[:operatingsystem]) and facts[:operatingsystemmajrelease] < "7"
          then
            is_expected.to create_file('/etc/sysconfig/ldap').with_content(/SLAPD_OPTIONS.*slapd.conf/)
          else
            is_expected.to create_file('/etc/sysconfig/slapd').with_content(/SLAPD_URLS.*ldap.*:\/\//)
          end
        }

        context 'without_tls' do
          let(:pre_condition) {
            %(
              class { "::openldap": base_dn => "dc=host,dc=net" }
            )
          }
          let(:params) {{ :use_tls => false }}
          it { is_expected.to_not create_pki__copy('/etc/openldap') }
          it { is_expected.to create_file('/etc/openldap/slapd.conf').with_notify('Class[Openldap::Server::Service]') }
          it { is_expected.to create_file('/etc/openldap/slapd.conf').without_content(/TLSCertificateFile/) }
        end

        context 'with_tls' do
          let(:pre_condition) {
            %( class { "::openldap": base_dn => "dc=host,dc=net" })
          }
          let(:params) {{
            :use_tls => true
          }}
          it { is_expected.to create_file('/etc/openldap/slapd.conf').with({
            :notify => 'Class[Openldap::Server::Service]',
            :content => /TLSCertificateFile/
            })
          }
        end

        context 'with_tls_but_not_simp_managed' do
          let(:pre_condition) {
            %( class { "::openldap": base_dn => "dc=host,dc=net" })
          }
          let(:params) {{
            :use_tls => true,
            :syslog => false,
           }}
          it { is_expected.to create_file('/etc/openldap/slapd.conf').with({
              :notify => 'Class[Openldap::Server::Service]',
              :content => /TLSCertificateFile/
            })
          }
        end

        context 'force_log_quick_kill' do
          let(:pre_condition) {
            %( class { "::openldap": base_dn => "dc=host,dc=net" })
          }

          let(:params){{ :force_log_quick_kill => true }}

          it { is_expected.to create_incron__system_table('nuke_openldap_log_files').with_command('/bin/rm $@/$#') }
        end

        context 'enable_iptables' do
          # Testing this by setting the global override
          let(:pre_condition) {
            %( class { "::openldap": base_dn => "dc=host,dc=net" })
          }
          let(:params){{
            :firewall => true
          }}
          it { is_expected.to create_class('iptables') }
          it { is_expected.to create_iptables__listen__tcp_stateful('allow_ldap').with_dports(389) }
          it { is_expected.to create_iptables__listen__tcp_stateful('allow_ldaps').with_dports(636) }
        end

        context 'do_not_use_iptables' do
          # Testing this by setting the global override
          let(:pre_condition) {
            %( class { "::openldap": base_dn => "dc=host,dc=net" })
          }

          let(:params){{
            :firewall => false
          }}
          it { is_expected.to_not create_iptables__listen__tcp_stateful('allow_ldap') }
          it { is_expected.to_not create_iptables__listen__tcp_stateful('allow_ldaps') }
        end

        context 'use_iptables_no_listen_ldaps' do
          let(:pre_condition) {
            %( class { "::openldap": base_dn => "dc=host,dc=net" })
          }
          let(:params){{
            :listen_ldaps => false,
            :firewall     => true
          }}

          it { is_expected.to create_class('iptables') }
          it { is_expected.to create_iptables__listen__tcp_stateful('allow_ldap').with_dports(389) }
          it { is_expected.to_not create_iptables__listen__tcp_stateful('allow_ldaps') }
        end

        context 'use_iptables_no_listen_ldap_or_ldaps' do
          let(:pre_condition) {
            %( class { "::openldap": base_dn => "dc=host,dc=net" })
          }
          let(:params){{
            :listen_ldap  => false,
            :listen_ldaps => false,
            :firewall     => true
          }}

          it { is_expected.to create_class('iptables') }
          it { is_expected.to_not create_iptables__listen__tcp_stateful('allow_ldap') }
          it { is_expected.to_not create_iptables__listen__tcp_stateful('allow_ldaps') }
        end

        context 'audit_transactions' do
          let(:pre_condition) {
            %( class { "::openldap": base_dn => "dc=host,dc=net" })
          }
          let(:params){{
            :auditlog          => '/var/log/ldap_audit.log',
            :auditlog_rotate   => 'daily',
            :auditlog_preserve => 7,
            :syslog            => true,
            :logrotate         => true
          }}

          it { is_expected.to create_class('logrotate') }
          it { is_expected.to create_class('rsyslog') }

          it { is_expected.to create_file(params[:auditlog]) }
          it { is_expected.to create_logrotate__rule('slapd_audit_log').with({
              :log_files     => [params[:auditlog]],
              :create        => '0640 ldap ldap',
              :rotate_period => params[:auditlog_rotate],
              :rotate        => params[:auditlog_preserve]
            })
          }
          it { is_expected.to create_openldap__server__dynamic_include('auditlog').with_content(/auditlog #{params[:auditlog]}/) }
          it { is_expected.to create_rsyslog__rule__data_source('openldap_audit').with_rule(/File="#{params[:auditlog]}"/) }
          it { is_expected.to create_rsyslog__rule__drop('1_drop_openldap_passwords').with_rule(/contains\s+'Password::\s+'/) }
        end

        context 'audit_transactions_no_audit_to_syslog' do
          let(:pre_condition) {
            %( class { "::openldap": base_dn => "dc=host,dc=net" })
          }
          let(:params){{
            :auditlog          => '/var/log/ldap_audit.log',
            :auditlog_rotate   => 'daily',
            :auditlog_preserve => 7,
            :audit_to_syslog   => false,
            :syslog            => true,
            :logrotate         => true
          }}

          it { is_expected.to create_class('logrotate') }

          it { is_expected.to create_file(params[:auditlog]) }
          it { is_expected.to create_logrotate__rule('slapd_audit_log').with({
              :log_files     => [params[:auditlog]],
              :create        => '0640 ldap ldap',
              :rotate_period => params[:auditlog_rotate],
              :rotate        => params[:auditlog_preserve]
            })
          }
          it { is_expected.to create_openldap__server__dynamic_include('auditlog').with_content(/auditlog #{params[:auditlog]}/) }
          it { is_expected.to_not create_rsyslog__add_conf('openldap_audit') }
          it { is_expected.to_not create_rsyslog__rule__drop('1_drop_openldap_passwords') }
        end

        context 'logging_enabled' do
          let(:pre_condition) {
            %( class { "::openldap": base_dn => "dc=host,dc=net" })
          }
          let(:params){{
            :syslog      => true,
            :log_to_file => true,
            :log_file    => '/foo/bar',
            :logrotate   => true
          }}

          it { is_expected.to create_class('logrotate') }
          it { is_expected.to create_class('rsyslog') }

          it { is_expected.to create_rsyslog__rule__local('05_openldap_local').with_rule(/local4\.\*/) }
          it { is_expected.to create_logrotate__rule('slapd').with({
              :log_files => [params[:log_file]]
            })
          }
        end

        context 'logging_disabled' do
          let(:pre_condition) {
            %( class { "::openldap": base_dn => "dc=host,dc=net" })
          }

          let(:params){{
            :syslog => false,
          }}
          it { is_expected.to_not create_rsyslog__rule__local('05_openldap_local') }
          it { is_expected.to_not create_logrotate__rule('slapd') }
        end

        context 'threads_is_dynamic' do
          let(:facts){
            facts[:server_facts] = {
              :servername => facts[:fqdn],
              :serverip   => facts[:ipaddress]
            }
            facts[:processorcount] = 4

            facts
          }

          it { is_expected.to create_file('/etc/openldap/slapd.conf').with_content(/threads   16/) }
          it { is_expected.to create_file('/etc/openldap/slapd.conf').without_content(/threads   8/) }
        end

        context 'threads_is_user_overridden' do
          let(:pre_condition) {
            %( class { "::openldap": base_dn => "dc=host,dc=net" })
          }
          let(:params){{ :threads => 20 }}

          it { is_expected.to create_file('/etc/openldap/slapd.conf').with_content(/threads   20/) }
          it { is_expected.to create_file('/etc/openldap/slapd.conf').without_content(/threads   8/) }
          it { is_expected.to create_file('/etc/openldap/slapd.conf').without_content(/threads   16/) }
        end
      end
    end
  end
end
