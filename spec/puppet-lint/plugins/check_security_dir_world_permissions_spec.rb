require 'spec_helper'

describe 'security_file_with_world_permissions' do
  let(:msg) { 'File or directory definition with world permissions detected (security!)' }

  context 'with fix disabled' do

    context 'code having directory with world permissions' do
      let(:code) { "file { '/var/log':
  ensure => directory,
  mode => '0777',
  owner => 'root',
  group => 'root',
}" }

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a error' do
        expect(problems).to contain_error(msg).on_line(3).in_column(11)
      end
    end

    context 'code having no directory with world permissions' do
      let(:code) { "file { '/var/log':
  ensure => directory,
  mode => '0755',
  owner => 'root',
  group => 'root',
}" }

      it 'should not detect any problems' do
        expect(problems).to have(0).problems
      end
    end

  end
end
