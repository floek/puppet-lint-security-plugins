require 'puppet-lint-security-plugins'

# Needed: puppetlabs-apache module (https://forge.puppetlabs.com/puppetlabs/apache)
# Matches vhosts without ssl enabled
PuppetLint.new_check(:security_apache_no_ssl_vhost) do

  def check

    check_resource_index(
      :resource_type => 'apache::vhost',
      :severity => :warning,
      :message => 'Vhost without ssl detected (security!)'
    ) do |rule|

      ssl=get_value_token_for_parameter(rule[:tokens],'ssl')

      # all ssl enable parameters
      ssl_enabled=ssl.find_all do |token|
        ['true','1'].include? token.value
      end

      rule[:tokens].first if ssl_enabled.empty?

    end

  end
end
