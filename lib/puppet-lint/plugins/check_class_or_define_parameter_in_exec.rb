require 'puppet-lint-security-plugins'

# Matches class or defined_type parameters used in exec
PuppetLint.new_check(:security_class_or_define_parameter_in_exec) do
  def check

    check_resource_index(
      :resource_type => 'exec',
      :severity => :error,
      :message => 'Class or definded_type parameter in exec used (security!)'
    ) do |rule|

      class_definitions=class_indexes.find_all do |cd|
        resource_in_class_or_define?(rule,cd) 
      end

      defined_types=defined_type_indexes.find_all do |dt|
        resource_in_class_or_define?(rule,dt)
      end

      parameters=(class_definitions+defined_types).map do |h|
        h[:param_tokens].map {|t|t.value} unless h[:param_tokens].nil?
      end.flatten.compact

      exec_tokens=rule[:tokens]
      command_tokens=get_value_token_for_parameter(exec_tokens,'command')
      command_tokens.find_all do |token|
        token.type == :VARIABLE and (
          parameters.include? token.value or
          (defined_type_indexes.empty? and class_definitions.empty?)
        )
      end
    end

  end
end
