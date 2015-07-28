require 'puppet-lint-security-plugins'

# Needed: saz/ssh module (https://forge.puppetlabs.com/saz/ssh)
# Matches ssh resources with PermitRootLogin enabled
PuppetLint.new_check(:security_ssh_root_allowed) do

  def check

    check_resource_index(
      :resource_type => ['ssh','ssh::server'],
      :severity => :error,
      :message => 'SSH root login allowed (security!)'
    ) do |rule|

      options = get_hash_tokens_for_parameter(rule[:tokens],'options')#.each do |option|
      options += get_hash_tokens_for_parameter(rule[:tokens],'server_options')#.each do |option|
      permit_root_logins = get_value_token_for_parameter(options,'PermitRootLogin')

      permit_root_logins.find_all do |token|
        ['true','1','yes'].include? token.value
      end

    end

  end
end
