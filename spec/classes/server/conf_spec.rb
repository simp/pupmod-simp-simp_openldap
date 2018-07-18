require 'spec_helper'

slapd_content_nopki = <<EOM
include   /etc/openldap/schema/core.schema
include   /etc/openldap/schema/cosine.schema
include   /etc/openldap/schema/inetorgperson.schema
include   /etc/openldap/schema/nis.schema
include  /etc/openldap/schema/openssh-lpk.schema
include  /etc/openldap/schema/freeradius.schema
include  /etc/openldap/schema/autofs.schema

threads   8
pidfile   /var/run/openldap/slapd.pid
argsfile  /var/run/openldap/slapd.args


authz-policy to
authz-regexp
    "^uid=([^,]+),.*"
    "uid=$1,ou=People,DC=host,DC=net"



disallow bind_anon
conn_max_pending 100
conn_max_pending_auth 1000
disallow bind_anon tls_2_anon
idletimeout 0

sizelimit 500
timelimit 3600
writetimeout 0

sockbuf_max_incoming 262143
sockbuf_max_incoming_auth 4194303

loglevel stats sync

reverse-lookup off

database  bdb
suffix    "DC=host,DC=net"
rootdn    "cn=LDAPAdmin,ou=People,DC=host,DC=net"

rootpw    {SSHA}foobarbaz!!!!

directory /var/lib/ldap
checkpoint 1024 5
cachesize 10000
lastmod on
maxderefdepth 15
monitoring on
readonly off

index_substr_any_step 2
index_substr_any_len 4
index_substr_if_maxlen 4
index_substr_if_minlen 2
index_intlen 4

index objectClass                       eq,pres
index ou,cn,mail,surname,givenname      eq,pres,sub
index uidNumber,gidNumber,loginShell    eq,pres
index uid,memberUid                     eq,pres,sub
index nisMapName,nisMapEntry            eq,pres,sub

include /etc/openldap/slapd.access
include /etc/openldap/dynamic_includes
EOM

describe 'simp_openldap::server::conf' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts[:slapd_version] = '2.4.40'
          facts
        end

        let(:slapd_content_pki) {
%(include   /etc/openldap/schema/core.schema
include   /etc/openldap/schema/cosine.schema
include   /etc/openldap/schema/inetorgperson.schema
include   /etc/openldap/schema/nis.schema
include  /etc/openldap/schema/openssh-lpk.schema
include  /etc/openldap/schema/freeradius.schema
include  /etc/openldap/schema/autofs.schema

threads   8
pidfile   /var/run/openldap/slapd.pid
argsfile  /var/run/openldap/slapd.args


authz-policy to
authz-regexp
    "^uid=([^,]+),.*"
    "uid=$1,ou=People,DC=host,DC=net"


TLSCertificateFile /etc/pki/simp_apps/openldap/x509/public/#{facts[:fqdn]}.pub
TLSCertificateKeyFile /etc/pki/simp_apps/openldap/x509/private/#{facts[:fqdn]}.pem
TLSProtocolMin 3.3
TLSCipherSuite HIGH:-TLSv1:-SSLv3
TLSVerifyClient allow
TLSCRLCheck none
TLSCACertificatePath /etc/pki/simp_apps/openldap/x509/cacerts

security ssf=256 tls=256 update_ssf=256 simple_bind=256 update_tls=256
password-hash {SSHA}

disallow bind_anon
conn_max_pending 100
conn_max_pending_auth 1000
disallow bind_anon tls_2_anon
idletimeout 0

sizelimit 500
timelimit 3600
writetimeout 0

sockbuf_max_incoming 262143
sockbuf_max_incoming_auth 4194303

loglevel stats sync

reverse-lookup off

database  bdb
suffix    "DC=host,DC=net"
rootdn    "cn=LDAPAdmin,ou=People,DC=host,DC=net"

rootpw    {SSHA}foobarbaz!!!!

directory /var/lib/ldap
checkpoint 1024 5
cachesize 10000
lastmod on
maxderefdepth 15
monitoring on
readonly off

index_substr_any_step 2
index_substr_any_len 4
index_substr_if_maxlen 4
index_substr_if_minlen 2
index_intlen 4

index objectClass                       eq,pres
index ou,cn,mail,surname,givenname      eq,pres,sub
index uidNumber,gidNumber,loginShell    eq,pres
index uid,memberUid                     eq,pres,sub
index nisMapName,nisMapEntry            eq,pres,sub

include /etc/openldap/slapd.access
include /etc/openldap/dynamic_includes
)
}

        let(:pre_condition) {
          %(
            class { "::simp_openldap":
              base_dn   => "DC=host,DC=net",
              is_server => true
            }
          )
        }

        context 'with default parameters' do
          it { is_expected.to create_class('simp_openldap::server') }
          it { is_expected.to create_class('simp_openldap::server::conf::default_ldif') }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_file('/etc/openldap/DB_CONFIG').with_content(/set_data_dir/) }
          it { is_expected.to create_file('/etc/openldap/default.ldif').with_content(/dn: DC=host,DC=net/) }
          it { is_expected.to create_file('/etc/openldap/default.ldif').with_content(/pwdCheckModule: .*check_password.so/) }

          # Users
          it { is_expected.to create_file('/etc/openldap/default.ldif').with_content(/gidNumber: 100/) }

          # Administrators
          it { is_expected.to create_file('/etc/openldap/default.ldif').with_content(/gidNumber: 700/) }
          it {
            if facts[:operatingsystemmajrelease] < "7"
              is_expected.to create_file('/etc/sysconfig/ldap').with_content(/SLAPD_OPTIONS.*slapd.conf/)
            else
              is_expected.to create_file('/etc/sysconfig/slapd').with_content(/SLAPD_URLS.*ldap.*:\/\//)
            end
          }
          it { is_expected.to create_file('/etc/openldap/slapd.conf').with_content(slapd_content_nopki)}
        end

        context 'with pki = false' do
          let(:hieradata) { 'pki_false' }
          it { is_expected.to_not contain_class('pki') }
          it { is_expected.to_not create_pki__copy('openldap') }
          it { is_expected.to_not create_file('/etc/pki/simp_apps/openldap/x509')}
          it { is_expected.to create_file('/etc/openldap/slapd.conf') }
          it { is_expected.to create_file('/etc/openldap/slapd.conf').without_content(/TLSCertificateFile/) }
        end

        context 'with pki = true and openldap-server = 2.4.40' do
          let(:hieradata) { 'pki_true' }
          it { is_expected.to_not contain_class('pki') }
          it { is_expected.to create_pki__copy('openldap') }
          it { is_expected.to create_file('/etc/pki/simp_apps/openldap/x509')}
          it { is_expected.to create_file('/etc/openldap/slapd.conf').with_content(slapd_content_pki) }
        end

        context 'with pki = true and openldap-servers < 2.4.40' do
          let(:facts) do
            facts[:slapd_version] = '2.3.0'
            facts
          end
          let(:hieradata) { 'pki_true' }
          it { is_expected.to create_file('/etc/openldap/slapd.conf').without_content(/TLSProtocolMin/)}
          it { is_expected.to create_file('/etc/openldap/slapd.conf').with_content(/TLSCipherSuite DEFAULT:!MEDIUM/)}
        end

        context 'with pki = true and slapd_version = nil' do
          let(:facts) do
            facts
          end
          let(:hieradata) { 'pki_true' }
          it { is_expected.to create_file('/etc/openldap/slapd.conf').without_content(/TLSProtocolMin/)}
          it { is_expected.to create_file('/etc/openldap/slapd.conf').with_content(/TLSCipherSuite DEFAULT:!MEDIUM/)}
        end

        context 'with pki = simp' do
          let(:pre_condition) { "include 'simp_openldap'" }
          let(:hieradata) { 'pki_simp' }
          let(:params) {{ :syslog => false }}
          it { is_expected.to contain_class('pki') }
          it { is_expected.to create_pki__copy('openldap') }
          it { is_expected.to create_file('/etc/pki/simp_apps/openldap/x509')}
          it { is_expected.to create_file('/etc/openldap/slapd.conf').with_content(/TLSCertificateFile/) }
        end

        context 'force_log_quick_kill' do
          let(:pre_condition) { "include 'simp_openldap'" }
          let(:params){{ :force_log_quick_kill => true }}

          it { is_expected.to create_incron__system_table('nuke_openldap_log_files').with_command('/bin/rm $@/$#') }
        end

        context 'enable_iptables' do
          let(:pre_condition) { "include 'simp_openldap'" }
          let(:params){{ :firewall => true }}
          it { is_expected.to create_class('iptables') }
          it { is_expected.to create_iptables__listen__tcp_stateful('allow_ldap').with_dports(389) }
          it { is_expected.to create_iptables__listen__tcp_stateful('allow_ldaps').with_dports(636) }
        end

        context 'do_not_use_iptables' do
          let(:pre_condition) { "include 'simp_openldap'" }
          let(:params){{ :firewall => false }}
          it { is_expected.to_not create_iptables__listen__tcp_stateful('allow_ldap') }
          it { is_expected.to_not create_iptables__listen__tcp_stateful('allow_ldaps') }
        end

        context 'use_iptables_no_listen_ldaps' do
          let(:pre_condition) { "include 'simp_openldap'" }
          let(:params){{
            :listen_ldaps => false,
            :firewall     => true
          }}

          it { is_expected.to create_class('iptables') }
          it { is_expected.to create_iptables__listen__tcp_stateful('allow_ldap').with_dports(389) }
          it { is_expected.to_not create_iptables__listen__tcp_stateful('allow_ldaps') }
        end

        context 'use_iptables_no_listen_ldap_or_ldaps' do
          let(:pre_condition) { "include 'simp_openldap'" }
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
          let(:pre_condition) { "include 'simp_openldap'" }
          let(:params){{
            :auditlog          => '/var/log/ldap_audit.log',
            :auditlog_rotate   => 'daily',
            :auditlog_preserve => 7,
            :syslog            => true,
            :logrotate         => true,
            :log_to_file       => true
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
          it { is_expected.to create_simp_openldap__server__dynamic_include('auditlog').with_content(/auditlog #{params[:auditlog]}/) }
          it { is_expected.to create_rsyslog__rule__data_source('openldap_audit').with_rule(/File="#{params[:auditlog]}"/) }
          it { is_expected.to create_rsyslog__rule__drop('1_drop_openldap_passwords').with_rule(/contains\s+'Password::\s+'/) }

          it { is_expected.to create_rsyslog__rule__local('05_openldap_local').with_rule("prifilt('local4.*')") }
          it { is_expected.to create_logrotate__rule('slapd').with({
              :log_files                 => [ '/var/log/slapd.log' ],
              :missingok                 => true,
              :lastaction_restart_logger => true
            })
          }
        end

        context 'audit_transactions_no_audit_to_syslog' do
          let(:pre_condition) { "include 'simp_openldap'" }
          let(:params){{
            :auditlog          => '/var/log/ldap_audit.log',
            :auditlog_rotate   => 'daily',
            :auditlog_preserve => 7,
            :audit_to_syslog   => false,
            :syslog            => true,
            :logrotate         => true,
            :log_to_file       => true
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
          it { is_expected.to create_simp_openldap__server__dynamic_include('auditlog').with_content(/auditlog #{params[:auditlog]}/) }
          it { is_expected.to_not create_rsyslog__add_conf('openldap_audit') }
          it { is_expected.to_not create_rsyslog__rule__drop('1_drop_openldap_passwords') }

          it { is_expected.to create_rsyslog__rule__local('05_openldap_local').with_rule("prifilt('local4.*')") }
          it { is_expected.to create_logrotate__rule('slapd').with({
              :log_files                 => [ '/var/log/slapd.log' ],
              :missingok                 => true,
              :lastaction_restart_logger => true
            })
          }
        end

        context 'logging_enabled' do
          let(:pre_condition) { "include 'simp_openldap'" }
          let(:params){{
            :syslog      => true,
            :log_to_file => true,
            :log_file    => '/foo/bar',
            :logrotate   => true
          }}

          it { is_expected.to create_class('logrotate') }
          it { is_expected.to create_class('rsyslog') }

          it { is_expected.to create_rsyslog__rule__local('05_openldap_local').with_rule("prifilt('local4.*')") }
          it { is_expected.to create_logrotate__rule('slapd').with({
              :log_files                 => [params[:log_file]],
              :missingok                 => true,
              :lastaction_restart_logger => true
            })
          }
        end

        context 'logging_disabled' do
          let(:pre_condition) { "include 'simp_openldap'" }
          let(:params){{ :syslog => false }}
          it { is_expected.to_not create_rsyslog__rule__local('05_openldap_local') }
          it { is_expected.to_not create_logrotate__rule('slapd') }
        end

        context 'threads_is_dynamic' do
          let(:pre_condition) { "include 'simp_openldap'" }
          let(:facts){
            facts[:slapd_version] = '2.4.40'
            facts[:processorcount] = 4
            facts
          }

          it { is_expected.to create_file('/etc/openldap/slapd.conf').with_content(/threads   16/) }
          it { is_expected.to create_file('/etc/openldap/slapd.conf').without_content(/threads   8/) }
        end

        context 'threads_is_user_overridden' do
          let(:pre_condition) { "include 'simp_openldap'" }
          let(:params){{ :threads => 20 }}

          it { is_expected.to create_file('/etc/openldap/slapd.conf').with_content(/threads   20/) }
          it { is_expected.to create_file('/etc/openldap/slapd.conf').without_content(/threads   8/) }
          it { is_expected.to create_file('/etc/openldap/slapd.conf').without_content(/threads   16/) }
        end
      end
    end
  end
end
