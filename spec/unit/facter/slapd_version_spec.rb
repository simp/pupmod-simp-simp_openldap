require 'spec_helper'
describe 'slapd_version' do

  before :each do
    Facter.clear
  end

  context 'slapd command exists' do
    it 'returns the correct version of slapd' do
      Facter::Core::Execution.stubs(:which).with('slapd').returns('/sbin/slapd')
      Facter::Core::Execution.stubs(:execute).with('/sbin/slapd -VV 2>&1').returns("@(#) $OpenLDAP: slapd 2.4.40 (Nov  6 2016 01:21:28) $")
      expect(Facter.fact(:slapd_version).value).to eq('2.4.40')
    end
  end

  context 'slapd command does not exist' do
    it 'returns nil' do
      Facter::Core::Execution.stubs(:which).with('slapd').returns(nil)
      expect(Facter.fact(:slapd_version).value).to eq(nil)
    end
  end
end
