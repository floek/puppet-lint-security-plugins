require 'puppet-lint-security-plugins'

# Matches user resources creating a non root user with id 0
PuppetLint.new_check(:security_user_with_id_0_created) do

  def check

    check_resource_index(
      :resource_type => 'user',
      :severity => :error,
      :message => 'Another User with ID 0 would be created (security!)'
    ) do |rule|

      title=get_resource_title_for(rule)
      uids=get_value_token_for_parameter(rule[:tokens],'uid')
      allowdupes=get_value_token_for_parameter(rule[:tokens],'allowdupe')
      users=get_value_token_for_parameter(rule[:tokens],'name')
      users << title

      uid_zero=uids.find_all{|uid| uid.value == "0"}
      allowdupe_true=allowdupes.find_all{|allowdupe| allowdupe.value == "true"}

      rule[:tokens].first if (not users.include? 'root') and
        (not uid_zero.empty?) and (not allowdupe_true.empty?)
    end

  end
end
