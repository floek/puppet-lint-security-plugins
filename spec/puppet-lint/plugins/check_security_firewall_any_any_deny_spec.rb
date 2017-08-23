require 'spec_helper'

describe 'security_firewall_any_any_deny' do
  let(:msg) { 'Firewall any:all drop rule detected (security!)' }

  context 'with fix disabled' do
    context 'code having any:all drop rule in firewall with proto and ipv4 source given' do
      let(:code) { "
  firewall { '000_deny_any':
    proto   => 'all',
    source  => '0.0.0.0/0',
    action  => 'drop',
  }
                   " }

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a warning' do
        expect(problems).to contain_warning(msg).on_line(2).in_column(28)
      end
    end

    context 'code having any:all drop rule in firewall with proto and ipv6 source given' do
      let(:code) { "
  firewall { '000_deny_any':
    proto   => 'all',
    source  => '::',
    action  => 'drop',
  }
                   " }

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a warning' do
        expect(problems).to contain_warning(msg).on_line(2).in_column(28)
      end
    end

     context 'code having drop rule in firewall without proto and source given' do
      let(:code) { "
  firewall { '000_deny_any':
    action  => 'drop',
  }
                   " }

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a warning' do
        expect(problems).to contain_warning(msg).on_line(2).in_column(28)
      end
    end

     context 'code having drop rule in firewall without proto and source "::"' do
      let(:code) { "
  firewall { '000_deny_any':
    source  => '::',
    action  => 'drop',
  }
                   " }

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a warning' do
        expect(problems).to contain_warning(msg).on_line(2).in_column(28)
      end
    end

     context 'code having drop rule in firewall without proto and source "0.0.0.0/0"' do
      let(:code) { "
  firewall { '000_deny_any':
    source  => '0.0.0.0/0',
    action  => 'drop',
  }
                   " }

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a warning' do
        expect(problems).to contain_warning(msg).on_line(2).in_column(28)
      end
    end

     context 'code having drop rule in firewall without source and prot "all"' do
      let(:code) { "
  firewall { '000_deny_any':
    proto   => 'all',
    action  => 'drop',
  }
                   " }

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a warning' do
        expect(problems).to contain_warning(msg).on_line(2).in_column(28)
      end
    end

    context 'code having no any/any deny in firewall' do
      let(:code) { "
  firewall { 'deny_ssh':
    port    => [22],
    proto   => tcp,
    action  => 'drop',
  }
                   " }

      it 'should not detect any problems' do
        expect(problems).to have(0).problems
      end
    end
  end
end
