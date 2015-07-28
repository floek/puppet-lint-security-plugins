require 'puppet-lint-security-plugins'

# Matches file resources with mode defines world permissions (777)
PuppetLint.new_check(:security_file_with_world_permissions) do

  def check

    check_resource_index(
      :resource_type => 'file',
      :severity => :error,
      :message => 'File or directory definition with world permissions detected (security!)'
    ) do |rule|

      modes=get_value_token_for_parameter(rule[:tokens],'mode')
      modes.find_all do |token|
        token.value =~ /\A\d?666\z/ or # Files with 666
        token.value =~ /\A\d?777\z/ or # Files or directories with 777
        token.value =~ /\A(a|ugo|uog|guo|gou|oug|ogu|)=rwx?\z/ or
        token.value =~ /\A[ugo]=rwx?,[ugo]=rwx?,[ugo]=rwx?\z/ or
        token.value =~ /\A(ug|gu)=rwx?,[ugo]=rwx?\z/
      end
    end

  end
end
