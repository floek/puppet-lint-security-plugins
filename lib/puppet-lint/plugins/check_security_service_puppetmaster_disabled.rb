require 'puppet-lint-security-plugins'

# Matches class or defined_type parameters used in exec
PuppetLint.new_check(:security_service_puppetmaster_disabled) do
  def check

    check_resource_index(
      :resource_type => 'service',
      :severity => :warning,
      :message => 'Puppetmaster service disabled (security!)'
    ) do |rule|

      value_tokens=get_value_token_for_parameter(rule[:tokens],'ensure')

      title_token = get_resource_title_for(rule)
      title = title_token.value unless title_token.nil?

      value_tokens.find_all do |token|
        token.value == 'stopped' and title == 'puppetmaster'
      end
    end

  end
end
