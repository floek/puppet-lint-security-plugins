require 'spec_helper'

describe 'security_apt_no_key' do
  let(:msg) { 'APT Repository without key detected (security!)' }

  context 'with fix disabled' do
    context 'code having no key parameter in apt' do
      let(:code) { "
apt::source { 'puppetlabs':
  location => 'http://apt.puppetlabs.com',
  repos    => 'main',
}
      " }

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a error' do
        expect(problems).to contain_error(msg).on_line(2).in_column(27)
      end
    end

    context 'code having key parameter in apt' do
      let(:code) { "apt::source { 'puppetlabs':
  location => 'http://apt.puppetlabs.com',
  repos    => 'main',
  key      => {
    'id'     => '47B320EB4C7C375AA9DAE1A01054B7A24BD6EC30',
    'server' => 'pgp.mit.edu',
  },
}," }

      it 'should not detect any problems' do
        expect(problems).to have(0).problems
      end
    end
  end
end
