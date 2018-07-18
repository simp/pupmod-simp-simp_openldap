require 'spec_helper'

ldap_conf_content = {
  :default =>
    "URI                 ldap://server1.host.net ldap://server2.host.net\n" +
    "BASE                DC=host,DC=net\n" +
    "BINDDN              cn=hostAuth,ou=Hosts,DC=host,DC=net\n" +
    "REFERRALS           on\n" +
    "SIZELIMIT           0\n" +
    "TIMELIMIT           15\n" +
    "DEREF               never\n" +
    "TLS_CACERTDIR       /etc/pki/simp_apps/openldap/x509/cacerts\n" +
    "TLS_CIPHER_SUITE    DEFAULT:!MEDIUM\n" +
    "TLS_REQCERT         allow\n" +
    "TLS_CRLCHECK        none\n",

  :with_strip_128_bit_ciphers =>
    "URI                 ldap://server1.host.net ldap://server2.host.net\n" +
    "BASE                DC=host,DC=net\n" +
    "BINDDN              cn=hostAuth,ou=Hosts,DC=host,DC=net\n" +
    "REFERRALS           on\n" +
    "SIZELIMIT           0\n" +
    "TIMELIMIT           15\n" +
    "DEREF               never\n" +
    "TLS_CACERTDIR       /etc/pki/simp_apps/openldap/x509/cacerts\n" +
    "TLS_CIPHER_SUITE    AES256\n" +
    "TLS_REQCERT         allow\n" +
    "TLS_CRLCHECK        none\n",

  :without_strip_128_bit_ciphers =>
    "URI                 ldap://server1.host.net ldap://server2.host.net\n" +
    "BASE                DC=host,DC=net\n" +
    "BINDDN              cn=hostAuth,ou=Hosts,DC=host,DC=net\n" +
    "REFERRALS           on\n" +
    "SIZELIMIT           0\n" +
    "TIMELIMIT           15\n" +
    "DEREF               never\n" +
    "TLS_CACERTDIR       /etc/pki/simp_apps/openldap/x509/cacerts\n" +
    "TLS_CIPHER_SUITE    AES256:AES128\n" +
    "TLS_REQCERT         allow\n" +
    "TLS_CRLCHECK        none\n",

  :with_crlfile =>
    "URI                 ldap://server1.host.net ldap://server2.host.net\n" +
    "BASE                DC=host,DC=net\n" +
    "BINDDN              cn=hostAuth,ou=Hosts,DC=host,DC=net\n" +
    "REFERRALS           on\n" +
    "SIZELIMIT           0\n" +
    "TIMELIMIT           15\n" +
    "DEREF               never\n" +
    "TLS_CACERTDIR       /etc/pki/simp_apps/openldap/x509/cacerts\n" +
    "TLS_CIPHER_SUITE    DEFAULT:!MEDIUM\n" +
    "TLS_REQCERT         allow\n" +
    "TLS_CRLCHECK        none\n" +
    "TLS_CRLFILE         /some/path/my_crlfile\n",

  :without_tls =>
    "URI                 ldap://server1.host.net ldap://server2.host.net\n" +
    "BASE                DC=host,DC=net\n" +
    "BINDDN              cn=hostAuth,ou=Hosts,DC=host,DC=net\n" +
    "REFERRALS           on\n" +
    "SIZELIMIT           0\n" +
    "TIMELIMIT           15\n" +
    "DEREF               never\n"
}

ldaprc_content = {
  :default =>
    "# This file placed by Puppet, but may be modified\n" +
    "#\n" +
    "# If you need a fresh copy, simply delete the file and Puppet will regenerate\n" +
    "# it\n\n" +
    "TLS_CACERTDIR /etc/pki/simp_apps/openldap/x509/cacerts\n" +
    "TLS_CERT /etc/pki/simp_apps/openldap/x509/public/myserver.test.local.pub\n" +
    "TLS_KEY /etc/pki/simp_apps/openldap/x509/private/myserver.test.local.pem\n",

  :with_crlfile =>
    "# This file placed by Puppet, but may be modified\n" +
    "#\n" +
    "# If you need a fresh copy, simply delete the file and Puppet will regenerate\n" +
    "# it\n\n" +
    "TLS_CACERTDIR /etc/pki/simp_apps/openldap/x509/cacerts\n" +
    "TLS_CERT /etc/pki/simp_apps/openldap/x509/public/myserver.test.local.pub\n" +
    "TLS_KEY /etc/pki/simp_apps/openldap/x509/private/myserver.test.local.pem\n",

  :without_tls => ''
}

shared_examples_for "a ldap config generator" do
  it { is_expected.to compile.with_all_deps }
  it { is_expected.to create_class('simp_openldap') }
  it { is_expected.to create_class('simp_openldap::client') }
  it { is_expected.to create_file('/etc/openldap/ldap.conf').with_content( ldap_conf_content[content_option] ) }
    it {
      if ldaprc_content[content_option]
        is_expected.to create_file('/root/.ldaprc').with_content( ldaprc_content[content_option] )
      else
        is_expected.to create_file('/root/.ldaprc').with_content( ldaprc_content[:default] )
      end
  }
  it { is_expected.to create_package('nss-pam-ldapd') }
  it { is_expected.to create_package("openldap-clients.#{facts[:hardwaremodel]}") }
end

describe 'simp_openldap::client' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) {
        facts = os_facts.dup
        facts[:fqdn]   = 'myserver.test.local'
        facts[:domain] = 'host.net'
        facts
      }

      context 'Generates files with strip_128_bit_ciphers = true' do
        let(:hieradata) { 'pki_true' }
        let(:params) {{
          :strip_128_bit_ciphers => true,
          :tls_cipher_suite      => ['AES256','AES128']
        }}

        if os_facts[:os][:release][:major] < '7'
          context 'on EL6' do
            let(:content_option) { :with_strip_128_bit_ciphers }
            it_should_behave_like "a ldap config generator"
          end
        else
          context 'on EL7' do
            let(:content_option) { :without_strip_128_bit_ciphers }
            it_should_behave_like "a ldap config generator"
          end
        end
      end

      context 'Generates files with strip_128_bit_ciphers = false' do
        let(:hieradata) { 'pki_true' }
        let(:params) {{
          :strip_128_bit_ciphers => false,
          :tls_cipher_suite      => ['AES256','AES128']
        }}

        let(:content_option) { :without_strip_128_bit_ciphers }
        it_should_behave_like "a ldap config generator"
      end

      context 'Generates files with pki = false' do
        let(:hieradata) { 'pki_false' }
        let(:content_option) { :without_tls }
        it_should_behave_like "a ldap config generator"
      end

      context 'Generates files with pki = true but without CRL file by default' do
        let(:hieradata) { 'pki_true' }
        let(:content_option) { :default }
        it_should_behave_like "a ldap config generator"
      end

      context 'Generates files with use_tls = true and specified CRL file' do
        let(:content_option) { :with_crlfile }
        let(:params) {{
          :app_pki_crl => '/some/path/my_crlfile',
          :use_tls     => true
        }}
        it_should_behave_like "a ldap config generator"
      end
    end
  end
end
