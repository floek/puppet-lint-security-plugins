require 'puppet-lint-security-plugins'

# Matches regular expression without start or end of string (\A,\z)
# or line (^,$) range markers 
PuppetLint.new_check(:security_regex_unspecific) do

  def check

    start_or_end_of_line_or_string_used = /\A(\\A|\^).*(\\z|\$)\z/

    result = tokens.find_all do |token|
      token.type == :REGEX and 
        token.value !~ start_or_end_of_line_or_string_used
    end

    bulk_notify(
      :result => result,
      :severity => :warning,
      :message => 'Unspecific regex used, maybe too much is matched.'

    ) 
  end
end
