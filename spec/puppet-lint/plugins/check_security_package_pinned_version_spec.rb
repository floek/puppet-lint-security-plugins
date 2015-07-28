require 'spec_helper'

describe 'security_package_pinned_version' do
  let(:msg) { 'Package version pinned (security!)' }

  context 'with fix disabled' do
    context 'code having openssh with fixed version' do
      let(:code) { "

package { 'openssh':
  name    => $ssh,
  ensure  => '1:6.6p1-2ubuntu2',
  require => Package['openssl']
}

" }

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a warning' do
        expect(problems).to contain_warning(msg).on_line(5).in_column(14)
      end
    end

    context 'code having no openssh with fixed version' do
      let(:code) { "

package { 'openssh':
  name    => $ssh,
  ensure  => installed,
  require => Package['openssl']
}
" }

      it 'should not detect any problems' do
        expect(problems).to have(0).problems
      end
    end

  end
end
