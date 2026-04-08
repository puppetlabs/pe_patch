require 'spec_helper'
require 'open3'
require 'json'

RSpec.describe 'patch_server task' do
  let(:task_path) { File.expand_path('../../../tasks/patch_server.rb', __dir__) }
  let(:puppet_bin) { '/opt/puppetlabs/puppet/bin/puppet' }

  # Mock facts for a RedHat system with no updates in the cache
  let(:redhat_facts_no_updates) do
    {
      'values' => {
        'os' => {
          'family' => 'RedHat',
          'name' => 'RedHat',
          'release' => { 'major' => '8' }
        },
        'pe_patch' => {
          'package_update_count' => 0,
          'security_package_update_count' => 0,
          'package_updates' => [],
          'security_package_updates' => [],
          'pinned_packages' => [],
          'blocked' => 'false',
          'blocked_reasons' => '',
          'reboot_override' => 'default',
          'pre_patching_scriptpath' => '',
          'post_patching_scriptpath' => ''
        }
      }
    }
  end

  # Mock facts for a RedHat system with updates available
  let(:redhat_facts_with_updates) do
    facts = redhat_facts_no_updates.dup
    facts['values']['pe_patch']['package_update_count'] = 2
    facts['values']['pe_patch']['package_updates'] = ['kernel-uek.x86_64', 'e2fsprogs.x86_64']
    facts
  end

  before(:each) do
    # Mock the fact generation script existence
    allow(File).to receive(:exist?).and_call_original
    allow(File).to receive(:exist?).with('/opt/puppetlabs/pe_patch/pe_patch_fact_generation.sh').and_return(true)

    # Mock syslog logger
    require 'syslog/logger'
    allow(Syslog::Logger).to receive(:new).and_return(double('logger', info: nil, debug: nil, error: nil))
  end

  describe 'yum_params handling' do
    context 'when updatecount is zero and yum_params is set' do
      let(:task_input) do
        {
          'reboot' => 'never',
          'yum_params' => '--enablerepo=local*UEKR*current'
        }
      end

      it 'should NOT exit early and should run yum with the enablerepo parameter' do
        # Mock Open3.capture3 for puppet facts
        allow(Open3).to receive(:capture3).with(puppet_bin, 'facts', 'find')
          .and_return([redhat_facts_no_updates.to_json, '', 0])

        # Mock the fact generation script run
        allow(Open3).to receive(:capture3).with('/opt/puppetlabs/pe_patch/pe_patch_fact_generation.sh')
          .and_return(['', '', 0])

        # This is the key assertion - yum should be called with the enablerepo param
        # even though updatecount is 0
        expect(Open3).to receive(:popen2e).with(/yum --enablerepo=local\*UEKR\*current .* upgrade -y/)
          .and_return([
            double('stdin', close: nil),
            double('stderrout', close: nil, read_nonblock: ''),
            double('thread', alive?: false, value: double('status', exitstatus: 0), :[] => 12345)
          ])

        # Mock yum history commands for RHEL > 5
        allow(Open3).to receive(:capture3).with('yum --setopt=history_list_view=users history')
          .and_return(["ID     | Login user               | Date and time    \n----------------------------------------------\n    69 | System <unset>          | 2025-12-16 14:27", '', 0])

        allow(Open3).to receive(:capture3).with('yum history info 69')
          .and_return(["Return-Code    : Success", '', 0])

        # Run the task
        allow($stdin).to receive(:read).and_return(task_input.to_json)
        expect { load task_path }.to raise_error(SystemExit) do |e|
          expect(e.status).to eq(0)
        end
      end

      it 'should log that it is skipping early exit when yum_params is set' do
        logger = double('logger')
        allow(Syslog::Logger).to receive(:new).and_return(logger)

        allow(Open3).to receive(:capture3).with(puppet_bin, 'facts', 'find')
          .and_return([redhat_facts_no_updates.to_json, '', 0])
        allow(Open3).to receive(:capture3).with('/opt/puppetlabs/pe_patch/pe_patch_fact_generation.sh')
          .and_return(['', '', 0])

        # Expect the log message about skipping the count check
        expect(logger).to receive(:info).with(/Update count is zero but yum_params is set - skipping early exit/)

        allow(Open3).to receive(:popen2e).and_return([
          double('stdin', close: nil),
          double('stderrout', close: nil, read_nonblock: ''),
          double('thread', alive?: false, value: double('status', exitstatus: 0), :[] => 12345)
        ])

        allow(Open3).to receive(:capture3).with('yum --setopt=history_list_view=users history')
          .and_return(["    69 | System <unset>          | 2025-12-16 14:27", '', 0])
        allow(Open3).to receive(:capture3).with('yum history info 69')
          .and_return(["Return-Code    : Success", '', 0])

        allow($stdin).to receive(:read).and_return(task_input.to_json)
        expect { load task_path }.to raise_error(SystemExit)
      end
    end

    context 'when updatecount is zero and yum_params is NOT set' do
      let(:task_input) do
        {
          'reboot' => 'never'
        }
      end

      it 'should exit early with "No patches to apply" message' do
        allow(Open3).to receive(:capture3).with(puppet_bin, 'facts', 'find')
          .and_return([redhat_facts_no_updates.to_json, '', 0])
        allow(Open3).to receive(:capture3).with('/opt/puppetlabs/pe_patch/pe_patch_fact_generation.sh')
          .and_return(['', '', 0])

        # yum should NOT be called in this case
        expect(Open3).not_to receive(:popen2e)

        allow($stdin).to receive(:read).and_return(task_input.to_json)

        # Capture the output
        output = nil
        allow($stdout).to receive(:puts) { |arg| output = arg }

        expect { load task_path }.to raise_error(SystemExit) do |e|
          expect(e.status).to eq(0)
          parsed_output = JSON.parse(output)
          expect(parsed_output['message']).to eq('No patches to apply')
        end
      end
    end

    context 'when updatecount is zero with reboot=always and yum_params set' do
      let(:task_input) do
        {
          'reboot' => 'always',
          'yum_params' => '--enablerepo=local*UEKR*current'
        }
      end

      it 'should still run yum with enablerepo before triggering reboot' do
        allow(Open3).to receive(:capture3).with(puppet_bin, 'facts', 'find')
          .and_return([redhat_facts_no_updates.to_json, '', 0])
        allow(Open3).to receive(:capture3).with('/opt/puppetlabs/pe_patch/pe_patch_fact_generation.sh')
          .and_return(['', '', 0])

        # yum SHOULD be called even with reboot=always when yum_params is set
        expect(Open3).to receive(:popen2e).with(/yum --enablerepo=local\*UEKR\*current/)
          .and_return([
            double('stdin', close: nil),
            double('stderrout', close: nil, read_nonblock: ''),
            double('thread', alive?: false, value: double('status', exitstatus: 0), :[] => 12345)
          ])

        allow(Open3).to receive(:capture3).with('yum --setopt=history_list_view=users history')
          .and_return(["    69 | System <unset>          | 2025-12-16 14:27", '', 0])
        allow(Open3).to receive(:capture3).with('yum history info 69')
          .and_return(["Return-Code    : Success", '', 0])

        # Mock reboot command
        allow(Process).to receive(:fork).and_return(12345)
        allow(Process).to receive(:detach)

        allow($stdin).to receive(:read).and_return(task_input.to_json)
        expect { load task_path }.to raise_error(SystemExit) do |e|
          expect(e.status).to eq(0)
        end
      end
    end

    context 'when yum_params contains unsafe characters' do
      let(:task_input) do
        {
          'reboot' => 'never',
          'yum_params' => '--enablerepo=test; rm -rf /'
        }
      end

      it 'should error out with unsafe content message' do
        allow(Open3).to receive(:capture3).with(puppet_bin, 'facts', 'find')
          .and_return([redhat_facts_no_updates.to_json, '', 0])
        allow(Open3).to receive(:capture3).with('/opt/puppetlabs/pe_patch/pe_patch_fact_generation.sh')
          .and_return(['', '', 0])

        allow($stdin).to receive(:read).and_return(task_input.to_json)

        output = nil
        allow($stdout).to receive(:puts) { |arg| output = arg }

        expect { load task_path }.to raise_error(SystemExit) do |e|
          expect(e.status).to eq(110)
          parsed_output = JSON.parse(output)
          expect(parsed_output['_error']['kind']).to eq('pe_patch/yum_params')
          expect(parsed_output['_error']['msg']).to include('Unsafe content in yum_params')
        end
      end
    end
  end

  describe 'zypper_params handling on SUSE' do
    let(:suse_facts_no_updates) do
      {
        'values' => {
          'os' => {
            'family' => 'Suse',
            'name' => 'SLES',
            'release' => { 'major' => '15' }
          },
          'pe_patch' => {
            'package_update_count' => 0,
            'security_package_update_count' => 0,
            'package_updates' => [],
            'security_package_updates' => [],
            'pinned_packages' => [],
            'blocked' => 'false',
            'blocked_reasons' => '',
            'reboot_override' => 'default',
            'pre_patching_scriptpath' => '',
            'post_patching_scriptpath' => ''
          }
        }
      }
    end

    context 'when updatecount is zero and zypper_params is set' do
      let(:task_input) do
        {
          'reboot' => 'never',
          'zypper_params' => '--plus-repo=custom_repo'
        }
      end

      it 'should NOT exit early and should run zypper with the custom repo parameter' do
        allow(Open3).to receive(:capture3).with(puppet_bin, 'facts', 'find')
          .and_return([suse_facts_no_updates.to_json, '', 0])
        allow(Open3).to receive(:capture3).with('/opt/puppetlabs/pe_patch/pe_patch_fact_generation.sh')
          .and_return(['', '', 0])

        # zypper should be called with the custom params even though updatecount is 0
        expect(Open3).to receive(:popen2e).with(/zypper .* --plus-repo=custom_repo .* update/)
          .and_return([
            double('stdin', close: nil),
            double('stderrout', close: nil, read_nonblock: ''),
            double('thread', alive?: false, value: double('status', exitstatus: 0), :[] => 12345)
          ])

        allow($stdin).to receive(:read).and_return(task_input.to_json)
        expect { load task_path }.to raise_error(SystemExit) do |e|
          expect(e.status).to eq(0)
        end
      end
    end
  end

  describe 'integration scenario - customer bug reproduction' do
    context 'Oracle Linux with disabled UEKR7 repo' do
      let(:oracle_facts_no_uek_updates) do
        {
          'values' => {
            'os' => {
              'family' => 'RedHat',
              'name' => 'OracleLinux',
              'release' => { 'major' => '8' }
            },
            'pe_patch' => {
              'package_update_count' => 0,  # No updates in default enabled repos
              'security_package_update_count' => 0,
              'package_updates' => [],  # UEK packages not shown because repo is disabled
              'security_package_updates' => [],
              'pinned_packages' => [],
              'blocked' => 'false',
              'blocked_reasons' => '',
              'reboot_override' => 'default',
              'pre_patching_scriptpath' => '',
              'post_patching_scriptpath' => ''
            }
          }
        }
      end

      let(:task_input) do
        {
          'reboot' => 'never',
          'yum_params' => '--enablerepo=local*UEKR*current'
        }
      end

      it 'should run yum with enablerepo flag to install UEK updates from disabled repo' do
        allow(Open3).to receive(:capture3).with(puppet_bin, 'facts', 'find')
          .and_return([oracle_facts_no_uek_updates.to_json, '', 0])
        allow(Open3).to receive(:capture3).with('/opt/puppetlabs/pe_patch/pe_patch_fact_generation.sh')
          .and_return(['', '', 0])

        # The key fix: yum runs with --enablerepo even when cached update count is 0
        expect(Open3).to receive(:popen2e).with(/yum --enablerepo=local\*UEKR\*current .* upgrade -y/)
          .and_return([
            double('stdin', close: nil),
            double('stderrout', close: nil, read_nonblock: 'Updating: kernel-uek'),
            double('thread', alive?: false, value: double('status', exitstatus: 0), :[] => 12345)
          ])

        # Mock yum history to show UEK kernel was updated
        allow(Open3).to receive(:capture3).with('yum --setopt=history_list_view=users history')
          .and_return(["    70 | System <unset>          | 2025-12-16 15:30", '', 0])
        allow(Open3).to receive(:capture3).with('yum history info 70')
          .and_return(["Return-Code    : Success", '', 0])
        allow(Open3).to receive(:capture3).with('yum history info 70').and_return([
          "Updated     kernel-uek.x86_64\nUpdated     e2fsprogs.x86_64",
          '', 0
        ])

        allow($stdin).to receive(:read).and_return(task_input.to_json)

        output = nil
        allow($stdout).to receive(:puts) { |arg| output = arg }

        expect { load task_path }.to raise_error(SystemExit) do |e|
          expect(e.status).to eq(0)
        end
      end
    end
  end
end

