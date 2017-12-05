require "spec_helper"
require "serverspec"

service = "isakmpd"
config  = "/etc/ipsec.conf"
_user    = "_isakmpd"
_group   = "_isakmpd"
ports = [500, 4500]
conf_dir = "/etc/pf.conf.d"

describe file(conf_dir) do
  it { should be_directory }
end

describe file("#{conf_dir}/ipsec_anchor.pf") do
  it { should be_file }
  its(:content) { should match(/pass in quick on egress proto udp from \$isakmpd_me to <ipsec_peers> port \{ 500, 4500 \}/) }
  its(:content) { should match(/pass in quick on egress proto udp from \$isakmpd_me to any port \{ 500, 4500 \}/) }
end

describe command("pfctl -sA") do
  its(:stdout) { should match(/ipsec_anchor/) }
end

describe command("pfctl -sr -a ipsec_anchor") do
  its(:stdout) { should match(/#{Regexp.escape('pass in quick on egress inet proto udp from 192.168.68.1 to any port = 500')}/) }
  its(:stdout) { should match(/#{Regexp.escape('pass in quick on egress inet proto udp from 192.168.68.1 to any port = 4500')}/) }
end

describe file("/etc/rc.conf.local") do
  it { should be_file }
  its(:content) { should match(/isakmpd_flags=-K/) }
  its(:content) { should match(/ipsec=YES/) }
end

describe file(config) do
  it { should be_file }

  its(:content) { should match(/#{Regexp.escape('me = "192.168.68.1"')}/) }

  its(:content) { should match(/^ike esp from \$me to \$peer2 peer \$peer2 \\\n\s+main auth hmac-sha1 enc aes-128 group modp1024 lifetime 10m \\\n\s+quick auth hmac-sha1 enc aes-128 group modp1024 lifetime 3600 \\\n\s+psk password$/) }
  its(:content) { should match(/^ike passive esp transport \\\n\s+proto udp from \$me to any port 1701 \\\n\s+main auth hmac-sha1 enc 3des group modp1024 lifetime 1200 \\\n\s+quick auth hmac-sha2-256 enc aes group modp1024 \\\n\s+psk password$/) }
end

describe service(service) do
  it { should be_running }
  it { should be_enabled }
end

ports.each do |p|
  describe port(p) do
    it { should be_listening.with("udp") }
  end
end
