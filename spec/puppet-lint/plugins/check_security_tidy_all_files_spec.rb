require 'spec_helper'

describe 'security_tidy_all_files' do
  let(:msg) { 'Purging all files, be warned!' }

  context 'with fix disabled' do
    context 'code having unspecific tidy' do
      let(:code) { "
tidy { '/usr/local':
}
" }

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a warning' do
        expect(problems).to contain_warning(msg).on_line(2).in_column(21)
      end
    end

    context 'code having specific tidy' do
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
