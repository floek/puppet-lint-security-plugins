require 'puppet-lint-security-plugins'

# Needed: puppetlabs-firewall module (https://forge.puppetlabs.com/puppetlabs/firewall)
# Matches firewall resources with source and destination equals 'drop'
PuppetLint.new_check(:security_firewall_any_any_deny) do

  def check

    check_resource_index(
      :resource_type => 'firewall',
      :severity => :warning,
      :message => 'Firewall any:all drop rule detected (security!)'
    ) do |rule|

      protos=get_value_token_for_parameter(rule[:tokens],'proto').map {|t| t.value}
      protos_bad = ( protos.include? 'all' or protos.empty? )

      sources=get_value_token_for_parameter(rule[:tokens],'source').map {|t| t.value}
      sources_bad = ( sources.include? '0.0.0.0/0' or sources.include? '::' or sources.empty? )

      actions=get_value_token_for_parameter(rule[:tokens],'action').map {|t| t.value}

      rule[:tokens].first if protos_bad and sources_bad and actions.include? "drop"
    end

  end
end
