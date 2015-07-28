require 'spec_helper'

describe 'security_class_or_define_parameter_in_exec' do
  let(:msg) { 'Class or definded_type parameter in exec used (security!)' }

  context 'with fix disabled' do
    context 'code having variables in execs' do
      let(:code) { "
class test ($command_var){
  exec { 'exec_echo_name':
    command => \"${command_var}\";
  }
}
                   "}

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a error' do
        expect(problems).to contain_error(msg).on_line(4).in_column(18)
      end
    end

    context 'code having variable only in exec' do
      let(:code) { "
class test ($command_var){
  exec { 'exec_echo_name':
    command => $command_var;
  }
}
                   "}

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a error' do
        expect(problems).to contain_error(msg).on_line(4).in_column(16)
      end
    end


    context 'code having four variables in execs' do
      let(:code) { "exec { 'exec_echo_name': command => \"/bin/echo ${name} jonoin ${name} hiohoi ${name} ihoiphoi${name}\"; }" }
      it 'should detect a single problem' do
        expect(problems).to have(4).problem
      end

    end

    context 'code having no variables in exec' do
      let(:code) { "
class test {

  exec { 'exec_command': command => \"${command_var}\"; }

  exec { 'exec_echo_name': command => \"/bin/echo hello\"; }

  exec { 'killall_puppet_user':
    command => \"/usr/bin/killall -9 -u puppet\",
    onlyif  => \"/usr/bin/pgrep -u puppet >/dev/null 2>&1\",
  }

  exec { 'del_puppet_user':
    command => '/usr/sbin/deluser --system -q puppet && /bin/sed -i \"/puppet/d\" /var/lib/dpkg/statoverride',
    onlyif  => \"/bin/grep '^puppet:' /etc/passwd\",
    require => Exec['killall_puppet_user'],
    before  => Class['http'],
  }

  # Notwendig, damit die ca_crl erzeugt wird. Sonst startet der Apache nicht
  exec { \"/usr/bin/puppet cert list\":
    creates => [\"/var/lib/puppet/ssl/ca/ca_crl.pem\"],
    require => Package[\"puppetmaster\"],
  }
}
" }

      it 'should not detect any problems' do
        expect(problems).to have(0).problems
      end
    end
  end
end
