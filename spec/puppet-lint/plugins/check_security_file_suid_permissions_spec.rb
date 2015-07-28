require 'spec_helper'

describe 'security_file_with_setuid_permission' do
  let(:msg) { 'File or directory definition with setuid to root detected (security!)'}

  context 'with fix disabled' do

    context 'code having file with suid permissions' do
      let(:code) { "

file { '/usr/local/bin/myscript':
  ensure => present,
  mode => '1755',
  owner => 'root',
  group => 'root',
  source => 'puppet:///modules/myscript/usr_local_bin_myscript',
}

                   " }

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a warning' do
        expect(problems).to contain_error(msg).on_line(5).in_column(11)
      end
    end

    context 'code having no file with suid permissions' do
      let(:code) { "

file { '/usr/local/bin/myscript':
  ensure => present,
  mode => '755',
  owner => 'root',
  group => 'root',
  source => 'puppet:///modules/myscript/usr_local_bin_myscript',
}
                   " }

      it 'should not detect any problems' do
        expect(problems).to have(0).problems
      end
    end

  end
end
