require 'puppet-lint-security-plugins'

# Matches variable definitions wich may store passwords in clear text
PuppetLint.new_check(:security_password_in_code) do

  def check
    passwords=/\A.*(passwor[dt]|_pwd?).*\z/i

    variables_with_passwords=tokens.find_all do |token|
      if token.type == :VARIABLE and token.value =~ passwords
        value_token=get_variable_value_for(token) # maybe nil, if just a class parameter
      end
      is_a_good_password_variable = ( value_token.nil? or
                                     value_token.value == 'hiera' or
                                     value_token.value.empty? or
                                     (
                                       value_token.type != :STRING and
                                       value_token.type != :SSTRING
                                     )
                                    )
      not is_a_good_password_variable
    end

    bulk_notify(
      :result => variables_with_passwords,
      :severity => :error,
      :message => 'Possible password in code detected (security!)'
    )

  end
end
