require 'puppet-lint-security-plugins'

# Needed: puppetlabs-apt module (https://forge.puppetlabs.com/puppetlabs/apt)
# Matches apt::source definitions without key parameter
PuppetLint.new_check(:security_apt_no_key) do

  def check

    check_resource_index(
      :resource_type => 'apt::source',
      :severity => :error,
      :message => 'APT Repository without key detected (security!)'
    ) do |rule|
      rule_tokens=rule[:tokens]
      ensures = get_value_token_for_parameter(rule[:tokens],'ensure')
      ensures.map! { |e| e.value }

      key_parameters=rule_tokens.find_all do |token|
        token.type == :NAME and token.value == 'key'
      end

      rule_tokens.first if key_parameters.empty? and not ensures.include? 'absent'
    end

  end
end
