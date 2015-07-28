require 'puppet-lint-security-plugins'

# Needed: puppetlabs-firewall module (https://forge.puppetlabs.com/puppetlabs/firewall)
# Matches firewall resources with source and destination equals 'drop'
PuppetLint.new_check(:security_firewall_puppetmaster_any_deny) do

  def check

    check_resource_index(
      :resource_type => 'firewall',
      :severity => :warning,
      :message => 'Firewall drops puppetmaster port (security!)'
    ) do |rule|

      parameter='port'

      if value_is_array?(rule[:tokens],parameter)
        ports=get_array_tokens_for_parameter(rule[:tokens],parameter).map{ |t| t.value}
      else
        ports=get_value_token_for_parameter(rule[:tokens],parameter).map {|t| t.value}
      end

      sources=get_value_token_for_parameter(rule[:tokens],'source').map {|t| t.value}
      sources_bad = ( sources.include? '0.0.0.0/0' or sources.include? '::' or sources.empty? )

      actions=get_value_token_for_parameter(rule[:tokens],'action').map {|t| t.value}
      actions.include? "drop"

      rule[:tokens].first if ports.include? '8140' and sources_bad and actions.include? 'drop'
    end

  end
end
