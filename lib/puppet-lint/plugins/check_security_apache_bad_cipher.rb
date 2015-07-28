require 'puppet-lint-security-plugins'
require 'openssl'

# Needed: puppetlabs-apache module (https://forge.puppetlabs.com/puppetlabs/apache)
# Matches mod_ssl cipher configuration, valid cipher list from https://cipherli.st
PuppetLint.new_check(:security_apache_bad_cipher) do

  def check

    ssl_context=OpenSSL::SSL::SSLContext.new
    ssl_context.ciphers='EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH:ECDHE-RSA-AES128-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA128:DHE-RSA-AES128-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA128:ECDHE-RSA-AES128-SHA384:ECDHE-RSA-AES128-SHA128:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA128:DHE-RSA-AES128-SHA128:DHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA384:AES128-GCM-SHA128:AES128-SHA128:AES128-SHA128:AES128-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4'
    good_ciphers=ssl_context.ciphers.flatten

    check_resource_index(
      :resource_type => 'apache::mod::ssl',
      :severity => :warning,
      :message => 'Unsecure ciphers used (security!)'
    ) do |rule|
      ssl_ciphers=get_value_token_for_parameter(rule[:tokens],'ssl_cipher')
      ssl_ciphers.find_all do |token|
        ssl_context.ciphers=token.value
        bad_ciphers=ssl_context.ciphers.flatten - good_ciphers
        not bad_ciphers.empty?
      end
    end

  end
end
