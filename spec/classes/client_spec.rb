require 'spec_helper'

ldap_conf_content = {
  :default =>
    "URI                 ldap://server1.bar.baz ldap://server2.bar.baz\n" +
    "BASE                ou=foo,dc=bar,dc=baz\n" +
    "BINDDN              cn=hostAuth,ou=Hosts,ou=foo,dc=bar,dc=baz\n" +
    "REFERRALS           on\n" +
    "SIZELIMIT           0\n" +
    "TIMELIMIT           15\n" +
    "DEREF               never\n" +
    "TLS_CACERTDIR       /etc/openldap/pki/cacerts\n" +
    "TLS_CIPHER_SUITE    DEFAULT:!MEDIUM\n" +
    "TLS_REQCERT         allow\n" +
    "TLS_CRLCHECK        none\n",

  :with_crlfile =>
    "URI                 ldap://server1.bar.baz ldap://server2.bar.baz\n" +
    "BASE                ou=foo,dc=bar,dc=baz\n" +
    "BINDDN              cn=hostAuth,ou=Hosts,ou=foo,dc=bar,dc=baz\n" +
    "REFERRALS           on\n" +
    "SIZELIMIT           0\n" +
    "TIMELIMIT           15\n" +
    "DEREF               never\n" +
    "TLS_CACERTDIR       /etc/openldap/pki/cacerts\n" +
    "TLS_CIPHER_SUITE    DEFAULT:!MEDIUM\n" +
    "TLS_REQCERT         allow\n" +
    "TLS_CRLCHECK        none\n" +
    "TLS_CRLFILE         /some/path/my_crlfile\n",

  :without_tls =>
    "URI                 ldap://server1.bar.baz ldap://server2.bar.baz\n" +
    "BASE                ou=foo,dc=bar,dc=baz\n" +
    "BINDDN              cn=hostAuth,ou=Hosts,ou=foo,dc=bar,dc=baz\n" +
    "REFERRALS           on\n" +
    "SIZELIMIT           0\n" +
    "TIMELIMIT           15\n" +
    "DEREF               never\n"
}

ldaprc_content = {
  :default =>
    "TLS_CACERTDIR /etc/openldap/pki/cacerts\n" +
    "TLS_CERT /etc/openldap/pki/public/myserver.test.local.pub\n" +
    "TLS_KEY /etc/openldap/pki/private/myserver.test.local.pem\n",

  :with_crlfile =>
    "TLS_CACERTDIR /etc/openldap/pki/cacerts\n" +
    "TLS_CERT /etc/openldap/pki/public/myserver.test.local.pub\n" +
    "TLS_KEY /etc/openldap/pki/private/myserver.test.local.pem\n",

  :without_tls => ""
}

shared_examples_for "a ldap config generator" do
  it { is_expected.to compile.with_all_deps }
  it { is_expected.to create_class('openldap') }
  it { is_expected.to create_class('openldap::client') }
  it { is_expected.to create_file('/etc/openldap/ldap.conf').with_content( ldap_conf_content[content_option] ) }
  it { is_expected.to create_file('/root/.ldaprc').with_content( ldaprc_content[content_option] ) }
  it { is_expected.to create_package('nss-pam-ldapd') }
  it { is_expected.to create_package("openldap-clients.#{facts[:hardwaremodel]}") }
end

describe 'openldap::client' do

  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) { facts.merge({ :fqdn => 'myserver.test.local' }) }
        let(:params) { { :use_tls => false }}
        context 'Generates files without TLS' do
          let(:content_option) { :without_tls }
          it_should_behave_like "a ldap config generator"
          it { is_expected.to_not create_pki__copy('/etc/openldap') }
        end
        let(:pre_condition) {
          %(
            class { "::openldap":
              base_dn   => "dc=host,dc=net",
              is_server => false,
            }
          )
        }

        context 'Generates files with TLS but without CRL file by default' do
          let(:params) { {
            :pki => false,
          } }
          let(:content_option) { :default }
          it_should_behave_like "a ldap config generator"
          it { is_expected.to_not create_pki__copy('/etc/openldap') }
        end

        context 'Generates files with TLS, without CRL, with pki = simp' do
          let(:params) { {
            :pki => 'simp',
          } }
          let(:content_option) { :default }
          it_should_behave_like "a ldap config generator"
          it { is_expected.to create_pki__copy('/etc/openldap') }
          it { is_expected.to contain_class('pki') }
        end

        context 'Generates files with TLS and specified CRL file' do
          let(:content_option) { :with_crlfile }
          let(:params) { {
            :tls_crlfile => '/some/path/my_crlfile',
            :pki => true
          } }
          it_should_behave_like "a ldap config generator"
          it { is_expected.to create_pki__copy('/etc/openldap') }
          it { is_expected.to_not contain_class('pki') }
        end

        context 'Generates files without TLS' do
          let(:content_option) { :without_tls }
          let(:params) { {
             :pki => false,
             :use_tls => false } }
          it_should_behave_like "a ldap config generator"
          it { is_expected.to_not create_pki__copy('/etc/openldap') }
        end
      end
    end
  end
end
