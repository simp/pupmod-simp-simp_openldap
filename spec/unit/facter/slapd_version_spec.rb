require 'spec_helper'
describe 'slapd_version' do
  before :each do
    Facter.clear
  end

  context 'slapd command exists' do
    it 'returns the correct version of slapd' do
      allow(Facter::Core::Execution).to receive(:which).with('slapd').and_return('/sbin/slapd')
      allow(Facter::Core::Execution).to receive(:execute).with('/sbin/slapd -VV 2>&1').and_return('@(#) $OpenLDAP: slapd 2.4.40 (Nov  6 2016 01:21:28) $')
      expect(Facter.fact(:slapd_version).value).to eq('2.4.40')
    end
  end

  context 'slapd command does not exist' do
    it 'returns nil' do
      allow(Facter::Core::Execution).to receive(:which).with('slapd').and_return(nil)
      expect(Facter.fact(:slapd_version).value).to eq(nil)
    end
  end
end
