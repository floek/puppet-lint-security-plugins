require 'puppet-lint-security-plugins'

# Matches file resources with setuid mode and owner root
PuppetLint.new_check(:security_file_with_setuid_permission) do

  def check

    check_resource_index(
      :resource_type => 'file',
      :severity => :error,
      :message => 'File or directory definition with setuid to root detected (security!)'
    ) do |rule|

      modes=get_value_token_for_parameter(rule[:tokens],'mode')
      owners=get_value_token_for_parameter(rule[:tokens],'owner')
      owners.map! {|t| t.value}
      modes.find_all do |token|
        owners.include? 'root' and
        token.value =~ /\A1\d\d\d\z/ or # Files or directories with setuid
        token.value =~ /\+s/ # setuid
      end
    end

  end
end
