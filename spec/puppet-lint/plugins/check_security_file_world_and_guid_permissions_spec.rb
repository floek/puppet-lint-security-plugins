require 'spec_helper'

describe 'security_file_with_world_permissions' do
  let(:msg) { 'File or directory definition with world permissions detected (security!)' }

  context 'with fix disabled' do
    context 'code having file with world permissions' do
      let(:code) { "

      file { \"/nfs/${targetpath}/foobar\":
        group   => 'roots',
        mode    => 2777,
        require => Autofs::Mount[$targetpath];
      }

" }

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a error' do
        expect(problems).to contain_error(msg).on_line(5).in_column(20)
      end
    end

    context 'code having file with no world permissions' do
      let(:code) { "

      file { \"/nfs/${targetpath}/foobar\":
        group   => 'roots',
        mode    => 0755,
        require => Autofs::Mount[$targetpath];
      }
" }

      it 'should not detect any problems' do
        expect(problems).to have(0).problems
      end
    end

  end
end
