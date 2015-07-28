require 'spec_helper'

describe 'security_password_variable_in_exec' do
  let(:msg) { 'Possible password variable in exec used (security!)' }

  context 'with fix disabled' do
    context 'code having password variables in execs' do
      let(:code) { "
exec {
  'exec_application':
    command => \"/usr/bin/application -p ${application_pwd_db}\";
  'exec_ldap':
    command => \"/usr/bin/ldapmodify -W${ldap_pw}\";
  'exec_db':
    command => \"/usr/bin/mysql -p ${db_password}\";
}
                   "}

      it 'should detect three problems' do
        expect(problems).to have(3).problem
      end

      it 'should create an error' do
        expect(problems).to contain_error(msg)
      end
    end

    context 'code having no variables in exec' do
      let(:code) { "
exec {
  'exec_application':
    command => \"/usr/bin/application -c /etc/app.rc\";
  'exec_ldap':
    command => \"/usr/bin/ldapmodify\";
  'exec_db':
    command => \"/usr/bin/mysql\";
}
                   " }

      it 'should not detect any problems' do
        expect(problems).to have(0).problems
      end
    end
  end
end
