require 'spec_helper'

describe 'security_firewall_any_any_allow' do
  let(:msg) { 'Firewall any/any allow rule detected (security!)' }

  context 'with fix disabled' do
    context 'code having any/any allow rule in firewall' do
      let(:code) { "firewall { 'allow_any':
    port    => 'any',
    source  => 'any',
    proto   => tcp,
    action  => 'accept',
      }" }

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a error' do
        expect(problems).to contain_error(msg).on_line(2).in_column(16)
      end
    end

    context 'code having no any/any allow rule in firewall' do
      let(:code) { "firewall { 'allow_ssh':
    port    => [22],
    proto   => tcp,
    action  => 'accept',
      }" }

      it 'should not detect any problems' do
        expect(problems).to have(0).problems
      end
    end
  end
end
