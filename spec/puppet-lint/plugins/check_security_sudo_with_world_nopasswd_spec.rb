require 'spec_helper'

# saz/sudo
describe 'security_sudo_with_world_nopasswd' do
  let(:msg) { 'Sudo access with world permissions detected (security!)' }

  context 'with fix disabled' do
    context 'code having sudo with world permissions' do
      let(:code) { "
sudo::conf { 'admins':
  priority => 10,
  content  => 'ALL ALL=(ALL) NOPASSWD: ALL',
}
" }

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a error' do
        expect(problems).to contain_error(msg).on_line(4).in_column(15)
      end
    end

    context 'code having no sudo with world permissions' do
      let(:code) { "

sudo::conf { 'admins':
  priority => 10,
  content  => '%admins ALL=(ALL) NOPASSWD: ALL',
}
" }

      it 'should not detect any problems' do
        expect(problems).to have(0).problems
      end
    end

  end
end
