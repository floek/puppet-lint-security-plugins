require 'puppet-lint-security-plugins'

# Matches package resources with specified version number
PuppetLint.new_check(:security_package_pinned_version) do

  def check

    check_resource_index(
      :resource_type => 'package',
      :severity => :warning,
      :message => 'Package version pinned (security!)'
    ) do |rule|

      ensures = get_value_token_for_parameter(rule[:tokens],'ensure')

      valid_values=['latest','purged','installed','present','installed','absent','held']

      ensures.find_all do |token|
        not valid_values.include? token.value
      end

    end

  end
end
