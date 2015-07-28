require 'spec_helper'

describe 'security_firewall_puppetmaster_any_deny' do
  let(:msg) { 'Firewall drops puppetmaster port (security!)' }

  context 'with fix disabled' do
    context 'code having rule droping puppetmaster port as array in firewall' do
      let(:code) { "
  firewall { '000_deny_puppetmaster':
    port    => [8140],
    proto   => tcp,
    action  => 'drop',
  }
                   " }

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a warning' do
        expect(problems).to contain_warning(msg).on_line(2).in_column(38)
      end
    end

    context 'code having rule droping puppetmaster port in firewall' do
      let(:code) { "
  firewall { '000_deny_puppetmaster':
    port    => 8140,
    proto   => tcp,
    source  => '::',
    action  => 'drop',
  }
                   " }

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a warning' do
        expect(problems).to contain_warning(msg).on_line(2).in_column(38)
      end
    end


    context 'code having no rule droping puppetmaster port in firewall' do
      let(:code) { "
  firewall { '000_allow_puppetmaster':
    port    => [8140],
    source  => 'any',
    proto   => tcp,
    action  => 'accept',
  }
                   " }

      it 'should not detect any problems' do
        expect(problems).to have(0).problems
      end
    end
  end
end
