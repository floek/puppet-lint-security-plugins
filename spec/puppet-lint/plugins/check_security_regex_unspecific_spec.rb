require 'spec_helper'

describe 'security_regex_unspecific' do
  let(:msg) { 'Unspecific regex used, maybe too much is matched.' }

  context 'with fix disabled' do
    context 'code having unspecific regex' do
      let(:code) { "
if $::kernelversion =~ /3.*/ {
  notice ('Linux Kernel 3 used')
}
" }

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a warning' do
        expect(problems).to contain_warning(msg).on_line(2).in_column(24)
      end
    end

    context 'code having specific regex' do
      let(:code) { "
if $::kernelversion =~ /\\A3.*\\z/ {
  notice ('Linux Kernel 3 used')
}

if $::kernelversion =~ /^3.*$/ {
  notice ('Linux Kernel 3 used')
}
" }

      it 'should not detect any problems' do
        expect(problems).to have(0).problems
      end
    end

  end
end
