require 'puppet-lint-security-plugins'

# Matches tidy resources with 'match' parameter equals '*'
PuppetLint.new_check(:security_tidy_matches_greedy) do

  def check

    check_resource_index(
      :resource_type => 'tidy',
      :severity => :warning,
      :message => 'This will delete all files, be warned!'
    ) do |rule|

      tokens=rule[:tokens]
      if value_is_array?(tokens,'matches')
        matches=get_array_tokens_for_parameter(tokens,'matches')
      else
        matches=get_value_token_for_parameter(tokens,'matches')
      end
      matches.find_all do |token|
        token.value == '*'
      end

    end
  end
end

