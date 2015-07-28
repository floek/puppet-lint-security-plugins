require 'puppet-lint-security-plugins'

# Matches file resources with setgit mode and group root
PuppetLint.new_check(:security_file_with_setgid_permission) do

  def check

    check_resource_index(
      :resource_type => 'file',
      :severity => :error,
      :message => 'File or directory definition with setgid to root detected (security!)'
    ) do |rule|

      modes=get_value_token_for_parameter(rule[:tokens],'mode')
      groups=get_value_token_for_parameter(rule[:tokens],'group')
      groups.map! {|t| t.value }
      modes.find_all do |token|
        groups.include? 'root' and
        token.value =~ /\A2\d\d\d\z/ or # Files or directories with setuid
        token.value =~ /\+S/ # setuid
      end
    end

  end
end
