require 'spec_helper'

describe 'security_apache_no_ssl_vhost' do
  let(:msg) { 'Vhost without ssl detected (security!)' }

  context 'with fix disabled' do
    context 'code having vhost wihtout ssl' do
      let(:code) { "
apache::vhost { 'fourth.example.com':
  docroot  => '/var/www/fourth',
}
" }

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a warning' do
        expect(problems).to contain_warning(msg).on_line(2).in_column(38)
      end
    end

    context 'code having vhost with ssl' do
      let(:code) { "
apache::vhost { 'fourth.example.com':
  port     => '443',
  docroot  => '/var/www/fourth',
  ssl      => true,
  ssl_cert => '/etc/ssl/fourth.example.com.cert',
  ssl_key  => '/etc/ssl/fourth.example.com.key',
}
" }

      it 'should not detect any problems' do
        expect(problems).to have(0).problems
      end
    end

  end
end
