require 'puppet-lint-security-plugins'

# Matches inline_template usage with ruby method 'eval'
PuppetLint.new_check(:security_eval_in_erb) do

  def check

    inline_template_args=get_argument_token_for_function(tokens,'inline_template')
    result=inline_template_args.find_all do |token|
      token.value =~/eval\(/
    end

    bulk_notify(
      :result => result,
      :severity => :error,
      :message => '"eval" ruby function used (security!)'

    )

  end
end
