require 'spec_helper'

describe 'security_password_in_code' do
  let(:msg) { 'Possible password in code detected (security!)' }

  context 'with fix disabled' do
    context 'code having cleartext passwords' do
      let(:code) { "
$db_password='OhBao5ho'
$ldap_pw='Ceeghoh5'
$application_pwd_db='aiMoi1af'

" }

      it 'should detect three problems' do
        expect(problems).to have(3).problem
      end

      it 'should create a error' do
        expect(problems).to contain_error(msg)
      end
    end

    context 'code having no cleartext passwords' do
      let(:code) { "
class myclass (
  $param1_password,
  $param2_password,
  $param3_password= '',
  $param4_password = '',
) {
  $db_password = hiera('db_password')
  $ldap_pw=hiera('ldap_pw')
  $application_pwd_db= hiera('application_pwd_db')
}

class mysql::params
{

  $packages = 'mysql-server'
  $packages_extra = 'maatkit'
  $service = 'mysql'
  $password = $mysql::my_password

}

" }

      it 'should not detect any problems' do
        expect(problems).to have(0).problems
      end
    end

  end
end
