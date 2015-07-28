require 'spec_helper'

describe 'security_user_with_id_0_created' do
  let(:msg) { 'Another User with ID 0 would be created (security!)' }

  context 'with fix disabled' do
    context 'code having user with id 0 created' do
      let(:code) { "

user {'myroot':
  ensure     => present,
  managehome => true,
  allowdupe  => true,
  shell      => '/bin/bash',
  password   => '$6$vvj6dlOH$ORJ0dok0GJIbuTMAexlSsxOHMBmtz1qCioS3xB4f3ap5azQdZjqRLzHpJhCNjAVsW3E3GtZwcnHJu/baLjhr3.',
  uid        => 0,
}

                   " }

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a error' do
        expect(problems).to contain_error(msg).on_line(3).in_column(16)
      end
    end

    context 'code having no user with id 0 created' do
      let(:code) { "
user {'myroot':
  ensure     => present,
  managehome => true,
  shell      => '/bin/bash',
  password   => '$6$vvj6dlOH$ORJ0dok0GJIbuTMAexlSsxOHMBmtz1qCioS3xB4f3ap5azQdZjqRLzHpJhCNjAVsW3E3GtZwcnHJu/baLjhr3.',
}

                   " }

      it 'should not detect any problems' do
        expect(problems).to have(0).problems
      end
    end

  end
end
