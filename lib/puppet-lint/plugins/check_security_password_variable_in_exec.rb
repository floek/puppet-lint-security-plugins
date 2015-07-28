require 'puppet-lint-security-plugins'

# Matches class or defined_type parameters used in exec
PuppetLint.new_check(:security_password_variable_in_exec) do
  def check

    check_resource_index(
      :resource_type => 'exec',
      :severity => :error,
      :message => 'Possible password variable in exec used (security!)'
    ) do |rule|

      passwords=/\A.*(passwor[dt]|_pwd?).*\z/i

      command_tokens=get_value_token_for_parameter(rule[:tokens],'command')
      command_tokens.find_all do |token|
        token.type == :VARIABLE and token.value =~ passwords
      end
    end

  end
end
