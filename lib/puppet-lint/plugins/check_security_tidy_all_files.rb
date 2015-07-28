require 'puppet-lint-security-plugins'

# Matches tidy resources without age and size parameters
PuppetLint.new_check(:security_tidy_all_files) do

  def check

    check_resource_index(
      :resource_type => 'tidy',
      :severity => :warning,
      :message => 'Purging all files, be warned!'
    ) do |rule|

      ages=get_value_token_for_parameter(rule[:tokens],'age')
      sizes=get_value_token_for_parameter(rule[:tokens],'size')
      rule[:tokens].first if (ages + sizes).empty?

    end
  end
end
