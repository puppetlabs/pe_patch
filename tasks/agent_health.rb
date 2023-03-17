#!/opt/puppetlabs/puppet/bin/ruby

require 'open3'
require 'time'
require 'json'
require 'socket'

# Lifted from https://github.com/puppetlabs/enterprise_tasks/blob/c8855bb3198567e40204178682b094f924af5754/lib/enterprise_tasks/puppet_helper.rb#L7
def puppet_bin
  if Gem.win_platform?
    require 'win32/registry'
    installed_dir =
      begin
        Win32::Registry::HKEY_LOCAL_MACHINE.open('SOFTWARE\Puppet Labs\Puppet') do |reg|
          # rubocop:disable Style/RescueModifier
          # Rescue missing key
          dir = reg['RememberedInstallDir64'] rescue ''
          # Both keys may exist, make sure the dir exists
          break dir if File.exist?(dir)

          # Rescue missing key
          reg['RememberedInstallDir'] rescue ''
          # rubocop:enable Style/RescueModifier
        end
      rescue Win32::Registry::Error
        # Rescue missing registry path
        ''
      end

    path =
      if installed_dir.empty?
        # Fall back to assuming it's on the PATH
        'puppet'
      else
        File.join(installed_dir, 'bin', 'puppet.bat')
      end
  else
    path = '/opt/puppetlabs/puppet/bin/puppet'
  end
  path
end

puppet_cmd = puppet_bin

output, stderr, status = Open3.capture3(puppet_cmd, 'config', 'print', '--section', 'agent', '--render-as', 'json')
if status != 0
  puts stderr
  exit 1
end

json = {}
details = {}
details['issues'] = {}

params = JSON.parse(STDIN.read)
config = JSON.parse(output)

noop_run = if params['_noop']
             true
           else
             false
           end

target_runinterval = if params['target_runinterval']
                       params['target_runinterval'].to_i
                     else
                       1800
                     end

target_noop_state = if params['target_noop_state'].nil?
                      false
                    else
                      params['target_noop_state']
                    end

target_use_cached_catalog_state = if params['target_use_cached_catalog_state'].nil?
                                    false
                                  else
                                    params['target_use_cached_catalog_state']
                                  end

target_service_enabled = if params['target_service_enabled'].nil?
                           true
                         else
                           params['target_service_enabled']
                         end

target_service_running = if params['target_service_running'].nil?
                           'running'
                         elsif params['target_service_running'] == true
                           'running'
                         elsif params['target_service_running'] == false
                           'stopped'
                         else
                           params['target_service_running']
                         end

certname              = config['certname']
pm_port               = config['masterport'].to_i
noop                  = config['noop']
use_cached_catalog    = config['use_cached_catalog']
lock_file             = config['agent_disabled_lockfile']
interval              = config['runinterval']
statedir              = config['statedir']
compilers             = config['server_list'].split(',')
puppetserver          = config['server']
ca_server             = config['ca_server']
requestdir            = config['requestdir']
certdir               = config['certdir']
last_run_summary_file = config['lastrunfile']
last_run_report_file  = config['lastrunreport']

if noop != target_noop_state
  details['issues']['noop'] = 'noop set to ' + noop.to_s + ' should be ' + target_noop_state.to_s
end

if use_cached_catalog != target_use_cached_catalog_state
  details['issues']['use_cached_catalog'] = 'use_cached_catalog set to ' + use_cached_catalog.to_s + ' should be ' + target_use_cached_catalog_state.to_s
end

if File.file?(lock_file)
  details['issues']['lock_file'] = 'agent disabled lockfile found'
end

if interval.to_i != target_runinterval
  details['issues']['runinterval'] = 'not set to ' + target_runinterval.to_s
end

run_time = 0
if File.file?(last_run_summary_file)
  last_run_contents = File.open(last_run_summary_file, 'r').read
  last_run_contents.each_line do |line|
    matchdata = line.match(%r{^\s*last_run: ([0-9]*)})
    next unless matchdata
    run_time = matchdata[1]
  end
  now = Time.new.to_i
  if (now - interval.to_i) > run_time.to_i
    details['issues']['last_run'] = 'Last run too long ago'
  end
  failcount = 0
  last_run_contents = File.open(last_run_summary_file, 'r').read
  last_run_contents.each_line do |line|
    matchdata = line.match(%r{.*(fail.*: [1-9]|skipped.*: [1-9])})
    next unless matchdata
    failcount += 1
  end
  if failcount > 0
    details['issues']['failures'] = 'Last run had failures'
  end
else
  details['issues']['last_run'] = 'Cannot locate file : ' + last_run
end

failcount = 0
if File.file?(last_run_report_file)
  report_contents = File.open(last_run_report_file, 'r').read
  report_contents.each_line do |line|
    matchdata = line.match(%r{status: failed})
    next unless matchdata
    failcount += 1
  end
  if failcount > 0
    details['issues']['catalog'] = 'Catalog failed to compile'
  end
end

_output, _stderr, status = Open3.capture3(puppet_cmd, 'ssl', 'verify')
if status != 0
  details['issues']['signed_cert'] = 'SSL verify error'
end

enabled = false
running = false
output, _stderr, _status = Open3.capture3(puppet_cmd, 'resource', 'service', 'puppet')
output.split("\n").each do |line|
  if line =~ %r{^\s+enable\s+=> '#{target_service_enabled}',$}
    enabled = true
  end
  if line =~ %r{^\s+ensure\s+=> '#{target_service_running}',$}
    running = true
  end
end

if enabled == false
  details['issues']['enabled'] = 'Puppet service enabled not set to ' + target_service_enabled.to_s
end

if running == false
  details['issues']['running'] = 'Puppet service not set to ' + target_service_running.to_s
end

if compilers[0]
  compilers.each do |compiler|
    begin
      TCPSocket.new(compiler.split(':')[0], pm_port)
    rescue
      details['issues']['port ' + compiler.split(':')[0]] = 'Port ' + pm_port.to_s + ' on ' + compiler.split(':')[0] + ' not reachable'
    end
  end
else
  begin
    TCPSocket.new(puppetserver.split(':')[0], pm_port)
  rescue
    details['issues']['port'] = 'Port ' + pm_port.to_s + ' on ' + puppetserver.split(':')[0] + ' not reachable'
  end
end

details['certname'] = certname
details['date'] = Time.now.iso8601
details['noop_run'] = noop_run

if details['issues'].empty?
  details['state'] = 'clean'
  json = details
  exit_code = 0
else
  details['state'] = 'issues found'
  exit_code = 1
  json[:_error] = { 
                    msg: "Issues found: " + details['issues'].to_s,
                    kind: 'pe_patch/agent_health',
                    details: details,
                  }
end

puts JSON.dump(json)
exit exit_code
