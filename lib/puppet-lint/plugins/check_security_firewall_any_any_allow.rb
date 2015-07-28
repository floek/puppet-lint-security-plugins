require 'puppet-lint-security-plugins'

# Needed: puppetlabs-firewall module (https://forge.puppetlabs.com/puppetlabs/firewall)
# Matches firewall resources with source and destination equals 'any'
PuppetLint.new_check(:security_firewall_any_any_allow) do

  def check

    check_resource_index(
      :resource_type => 'firewall',
      :severity => :error,
      :message => 'Firewall any/any allow rule detected (security!)'
    ) do |rule|

      rule_tokens=rule[:tokens]
      anies=rule_tokens.find_all do |token|
        (token.type == :NAME or token.type == :SSTRING) and
          token.value == 'any' and
          token.prev_code_token.type == :FARROW
      end

      anies.first if anies.count >= 2
    end

  end
end
