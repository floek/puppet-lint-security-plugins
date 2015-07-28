require 'spec_helper'

 describe 'security_firewall_dns_used' do
   let(:msg) { 'DNS in firewall rule used (security!)' }

   context 'with fix disabled' do
     context 'code having DNS hostname in firewall' do
       let(:code) { "

firewall { 'allow_ssh_from_dns_host':
    port    => 'ssh',
    source  => 'server.example.tld',
    proto   => tcp,
    action  => 'accept',
      }

" }

       it 'should detect a single problem' do
         expect(problems).to have(1).problem
       end

       it 'should create a error' do
         expect(problems).to contain_error(msg).on_line(5).in_column(16)
       end
     end

     context 'code having no DNS hostname in firewall' do
       let(:code) { "

  firewall { 'allow_ssh_from_host':
    port    => 'ssh',
    source  => '192.168.10.22',
    proto   => tcp,
    action  => 'accept',
      }

  firewall { '100 syslog server relp':
    proto  => 'tcp',
    dport  => [\"20514\"],
    source => \"10.0.0.0/16\",
    action => \"accept\",
  }

  firewall {
    '100 rpc 111/tcp':
      dport  => '111',
      proto  => 'tcp',
      source => $filer,
      action => 'accept';
    '101 statd/tcp':
      dport  => $nfs_statd_port,
      proto  => 'tcp',
      source => $filer,
      action => 'accept';
    '100 rpc 111/udp':
      dport  => '111',
      proto  => 'udp',
      source => $filer,
      action => 'accept';
    '101 statd/udp':
      dport  => $nfs_statd_port,
      proto  => 'udp',
      source => $filer,
      action => 'accept';

  }

" }

       it 'should not detect any problems' do
         expect(problems).to have(0).problems
       end
     end

   end
 end
