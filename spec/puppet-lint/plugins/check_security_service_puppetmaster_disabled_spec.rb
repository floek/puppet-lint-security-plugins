require 'spec_helper'

describe 'security_service_puppetmaster_disabled' do
  let(:msg) { 'Puppetmaster service disabled (security!)' }

  context 'with fix disabled' do
    context 'code having service puppetmaster disabled' do
      let(:code) { "
    service { 'puppetmaster':
      ensure     => stopped,
      enable     => false,
      hasrestart => true,
    }
" }

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a warning' do
        expect(problems).to contain_warning(msg).on_line(3).in_column(21)
      end
    end

    context 'code having service puppetmaster enabled' do
      let(:code) { "
    service { 'puppetmaster':
      ensure     => running,
      enable     => true,
      hasrestart => true,
    }
" }

      it 'should not detect any problems' do
        expect(problems).to have(0).problems
      end
    end

  end
end
