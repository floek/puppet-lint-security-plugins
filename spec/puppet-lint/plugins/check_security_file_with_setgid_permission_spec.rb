require 'spec_helper'

describe 'security_file_with_setgid_permission' do
  let(:msg) { 'File or directory definition with setgid to root detected (security!)'}

  context 'with fix disabled' do
    context 'code having file with setgid permissions' do
      let(:code) { "

file { '/bin/bash':
  mode => '2755',
  owner => 'root',
  group => 'root',
}

" }

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a error' do
        expect(problems).to contain_error(msg).on_line(4).in_column(11)
      end
    end

    context 'code having no file with setgid permissions' do
      let(:code) { "

file { '/bin/bash':
  mode => '0755',
  owner => 'root',
  group => 'root',
}

file {
  '/etc/icinga/commands.cfg':
    content => template('icinga/etc_icinga_commands.cfg'),
    notify  => Exec['icinga'],
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    require => Package['icinga'];
  '/usr/local/bin/icinga2ticket.rb':
    content  => template('icinga/usr_local_bin_icinga2ticket.rb'),
    notify  => Exec['icinga'],
    owner  => 'nagios',
    group  => 'nagios',
    mode   => '0750';
}
                   " }

      it 'should not detect any problems' do
        expect(problems).to have(0).problems
      end
    end

  end
end
