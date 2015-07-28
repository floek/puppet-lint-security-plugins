require 'puppet-lint-security-plugins'

# Needed: saz/sudo module (https://forge.puppetlabs.com/saz/sudo)
# Matches sudo resources with world root permissions
PuppetLint.new_check(:security_sudo_with_world_nopasswd) do

  def check
    bad_sudo_regex=/\AALL.*NOPASSWD.*\z/i

    check_resource_index(
      :resource_type => 'sudo::conf',
      :severity => :error,
      :message => 'Sudo access with world permissions detected (security!)'
    ) do |rule|

      sudo_rules=get_value_token_for_parameter(rule[:tokens],'content')
      sudo_rules.find_all do |token|
        token.value =~ bad_sudo_regex
      end
    end

  end
end
