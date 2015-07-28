require 'spec_helper'

describe 'security_apache_bad_cipher' do
  let(:msg) { 'Unsecure ciphers used (security!)' }

  context 'with fix disabled' do
    context 'code having unsecure ciphers' do
      let(:code) { "

class { 'apache::mod::ssl':
  ssl_compression        => false,
  ssl_options            => [ 'StdEnvVars' ],
  ssl_cipher             => 'HIGH:MEDIUM:!aNULL:!MD5',
  ssl_protocol           => [ 'all', '-SSLv2', '-SSLv3' ],
  ssl_pass_phrase_dialog => 'builtin',
  ssl_random_seed_bytes  => '512',
}

" }

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a warning' do
        expect(problems).to contain_warning(msg).on_line(6).in_column(29)
      end
    end

    context 'code having no unsecure ciphers' do
      let(:code) { "
# from https://cipherli.st/
class { 'apache::mod::ssl':
  ssl_compression        => false,
  ssl_options            => [ 'StdEnvVars' ],
  ssl_cipher             => 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH:ECDHE-RSA-AES128-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA128:DHE-RSA-AES128-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA128:ECDHE-RSA-AES128-SHA384:ECDHE-RSA-AES128-SHA128:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA128:DHE-RSA-AES128-SHA128:DHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA384:AES128-GCM-SHA128:AES128-SHA128:AES128-SHA128:AES128-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4',
  ssl_protocol           => [ 'all', '-SSLv2', '-SSLv3' ],
  ssl_pass_phrase_dialog => 'builtin',
  ssl_random_seed_bytes  => '512',
}
" }

      it 'should not detect any problems' do
        expect(problems).to have(0).problems
      end
    end

  end
end
