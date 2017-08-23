require 'spec_helper'

describe 'security_apt_no_key' do
  let(:msg) { 'APT Repository without key detected (security!)' }

  context 'with fix disabled' do


    context 'code having no key parameter in apt' do
      let(:code) { "

apt::source {
  'apt.postgresql.org':
    ensure => absent;
  'puppetlabs':
    location => 'http://apt.puppetlabs.com',
    repos    => 'main',
}

      " }

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a error' do
        expect(problems).to contain_error(msg).on_line(6).in_column(15)
      end
    end



    context 'code deleting apt repo' do
      let(:code) { "
    apt::source { 'apt.postgresql.org':
      ensure => absent,
    }
" }

      it 'should not detect any problems' do
        expect(problems).to have(0).problems
      end
    end
  end
end
