require 'puppet-lint-security-plugins'
require 'resolv'

# Needed: puppetlabs-firewall module (https://forge.puppetlabs.com/puppetlabs/firewall)
# Matches firewall resources without ip or subnet in source or destination
PuppetLint.new_check(:security_firewall_dns_used) do

  def check

    check_resource_index(
      :resource_type => 'firewall',
      :severity => :error,
      :message => 'DNS in firewall rule used (security!)'
    ) do |rule|

      source_and_destination=get_value_token_for_parameter(rule[:tokens],'source') +
        get_value_token_for_parameter(rule[:tokens],'destination')

      source_and_destination.find_all do |token|
        if [:STRING,:SSTRING].include? token.type
          host_or_network=token.value.split('/').first
          host_or_network !~ Resolv::IPv4::Regex and
            host_or_network !~ Resolv::IPv6::Regex
        end
      end

    end

  end
end
