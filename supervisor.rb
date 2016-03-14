#!/usr/bin/env ruby

interval = 10
TIMEOUT = 3

def exec host, cmd
  IO.popen(['ssh', '-oBatchMode=yes', "-oConnectTimeout=#{TIMEOUT}", host, '--', cmd]) {|f| f.read }
end

def notify title, body
  puts title, body
  #IO.popen ['notify-send', '-a', title, body]
end

checks = {
  #'gamebox_x64' => {
  #  host: 'ctf@10.5.8.4',
  #  commands: [
  #    ['killer', 'pgrep -x killer'],
  #    ['inotify-flag@rxc', 'pgrep -u rxc fff'],
  #    ['inotify-flag@tachikoma', 'pgrep -u tachikoma fff'],
  #  ]
  #},
  #'gamebox_mips': {
  #  host: 'ctf@10.5.8.2',
  #  commands: [
  #    ['inotify-flag@ombdsu', 'pgrep -u ombdsu fff'],
  #    ['inotify-flag@irkd', 'pgrep -u irkd fff'],
  #  ]
  #},
  'rr': {
    host: '10.5.8.105',
    commands: [
      ['download-pcap-regularly', 'pgrep -f download-pcap-regularly'],
      ['search@web', 'pgrep -f web.rb'],
      ['search@indexer', 'pgrep -f "indexer -ri /home/ray/defcon23"'],
      ['search@server', 'pgrep -f "indexer -r /home/ray/defcon23"'],
      ['search@pcap2ap', 'pgrep -f "pcap2ap -r /home/ray/defcon23"'],
    ]
  }
}

loop do
  now = Time.now
  for node, check in checks
    ssh_error = false
    bad = []
    for name, command in check[:commands]
      exec check[:host], command
      if $?.exitstatus == 255
        ssh_error = true
        break
      end
      bad << name if $?.exitstatus != 0
    end
    if ssh_error
      notify "monitor@#{node}", 'ssh error'
    elsif ! bad.empty?
      notify "monitor@#{node}", "bad: #{bad.join(', ')}"
    end
  end
  exit
  delay = Time.now+interval-now
  sleep delay if delay > 0
end
