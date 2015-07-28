require 'puppet-lint-security-plugins'

# Matches tidy resources with recurse parameter enabled
PuppetLint.new_check(:security_tidy_recurse) do

  def check

    check_resource_index(
      :resource_type => 'tidy',
      :severity => :warning,
      :message => 'Purging files recurse, be warned!'
    ) do |rule|

      recurses=get_value_token_for_parameter(rule[:tokens],'recurse')
      recurses.find_all do |token|
        ['true','1','inf'].include? token.value
      end
    end

  end
end
