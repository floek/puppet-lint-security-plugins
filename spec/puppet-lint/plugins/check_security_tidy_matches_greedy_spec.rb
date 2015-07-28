require 'spec_helper'

describe 'security_tidy_matches_greedy' do
  let(:msg) { 'This will delete all files, be warned!' }

  context 'with fix disabled' do
    context 'code having greedy tidy' do
      let(:code) { "
tidy { '/usr/local':
  matches => [ '[0-9]pub*.tmp', '*', '*.temp', 'tmpfile?' ]
}
" }

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a warning' do
        expect(problems).to contain_warning(msg).on_line(3).in_column(33)
      end
    end

    context 'code having no greedy tidy' do
      let(:code) { "
tidy { '/tmp':
  age     => '1w',
  matches => [ '[0-9]pub*.tmp', '*.temp', 'tmpfile?' ]
}
" }

      it 'should not detect any problems' do
        expect(problems).to have(0).problems
      end
    end

  end
end
