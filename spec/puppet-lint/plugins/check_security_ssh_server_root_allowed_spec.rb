require 'spec_helper'

# saz/ssh
describe 'security_ssh_root_allowed' do
  let(:msg) { 'SSH root login allowed (security!)' }

  context 'with fix disabled' do
    context 'code having ssh root login allowed' do
      let(:code) { "
class { 'ssh::server':
  options => {
    'Match User www-data' => {
      'ChrootDirectory' => '%h',
      'ForceCommand' => 'internal-sftp',
      'PasswordAuthentication' => 'yes',
      'AllowTcpForwarding' => 'no',
      'X11Forwarding' => 'no',
    },
    'PasswordAuthentication' => 'no',
    'PermitRootLogin'        => 'yes',
    'Port'                   => [22, 2222],
  },
}
" }

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a error' do
        expect(problems).to contain_error(msg).on_line(12).in_column(33)
      end
    end

    context 'code having ssh root login disabled' do
      let(:code) { "
class { 'ssh::server':
  options => {
    'Match User www-data' => {
      'ChrootDirectory' => '%h',
      'ForceCommand' => 'internal-sftp',
      'PasswordAuthentication' => 'yes',
      'AllowTcpForwarding' => 'no',
      'X11Forwarding' => 'no',
    },
    'PasswordAuthentication' => 'no',
    'PermitRootLogin'        => 'no',
    'Port'                   => [22, 2222],
  },
}

" }

      it 'should not detect any problems' do
        expect(problems).to have(0).problems
      end
    end

  end
end
