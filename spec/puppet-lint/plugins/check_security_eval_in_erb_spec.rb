require 'spec_helper'

describe 'security_eval_in_erb' do
  let(:msg) { '"eval" ruby function used (security!)' }

  context 'with fix disabled' do
    context 'code having eval in inline_template' do
      let(:code) { "
$test='p Dir.entries(\"/etc\")'
$variable = inline_template('<% eval(@test) %>')
notice($variable)
" }

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a error' do
        expect(problems).to contain_error(msg).on_line(3).in_column(29)
      end
    end

    context 'code having no eval in inline_template' do
      let(:code) { "
$variable = inline_template('<%= Dir.entries(\"/etc\") %>')
notice($variable)
" }

      it 'should not detect any problems' do
        expect(problems).to have(0).problems
      end
    end

  end
end
