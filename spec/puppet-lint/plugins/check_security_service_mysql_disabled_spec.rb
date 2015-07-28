require 'spec_helper'

describe 'security_service_mysql_disabled' do
  let(:msg) { 'MySQL service disabled (security!)' }

  context 'with fix disabled' do
    context 'code having service mysql disabled' do
      let(:code) { "
service {
  'mysql':
    ensure     => stopped,
    enable     => false,
    require    => Package['mysql'],
    hasrestart => true;
  'ntp':
    ensure     => stopped,
    enable     => false,
    require    => Package['ntp'],
    hasrestart => true;
}
" }

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a warning' do
        expect(problems).to contain_warning(msg).on_line(4).in_column(19)
      end
    end

    context 'code having service mysql enabled' do
      let(:code) { "

service { 'mysql':
   ensure     => running,
   enable     => true,
   hasrestart => true,
}

service {[\"cups\",\"cupsrenice\"]:
   enable =>  false,
   ensure => \"stopped\"
}

" }
      it 'should not detect any problems' do
        expect(problems).to have(0).problems
      end
    end

  end
end

