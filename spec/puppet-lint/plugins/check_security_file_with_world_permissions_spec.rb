require 'spec_helper'

describe 'security_file_with_world_permissions' do
  let(:msg) { 'File or directory definition with world permissions detected (security!)' }

  context 'with fix disabled' do
    context 'code having file with world permissions' do
      let(:code) { "

file { '/etc/passwd':
  ensure => present,
  mode => '0666',
  owner => 'root',
  group => 'root',
  source => 'puppet:///modules/passwd/etc_passwd',
}

" }

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a error' do
        expect(problems).to contain_error(msg).on_line(5).in_column(11)
      end
    end

    context 'code having file with no world permissions' do
      let(:code) { "
file { '/etc/passwd':
  ensure => present,
  mode => '0644',
  owner => 'root',
  group => 'root',
  source => 'puppet:///modules/passwd/etc_passwd',
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
