require 'spec_helper'

describe 'pe_patch::cleanup_os_patching' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      # rubocop:disable RSpec/ScatteredLet
      case os_facts[:kernel]
      when 'Linux'
        let(:cache_dir) { '/var/cache/os_patching' }
        let(:fact_dir) { '/usr/local/bin' }
        let(:fact_file) { 'os_patching_fact_generation.sh' }
      when 'windows'
        let(:cache_dir) { 'C:/ProgramData/os_patching' }
        let(:fact_dir) { cache_dir }
        let(:fact_file) { 'os_patching_fact_generation.ps1' }
      end
      let(:fact_cmd) { "#{fact_dir}/#{fact_file}" }

      it { is_expected.to contain_file(fact_cmd).with_ensure('absent').that_comes_before("File[#{cache_dir}]") }
      it { is_expected.to contain_file(cache_dir).with_ensure('absent').with_force(true) }

      case os_facts[:kernel]
      when 'Linux'
        it { is_expected.to contain_cron('Cache patching data').with_ensure('absent') }
        it { is_expected.to contain_cron('Cache patching data at reboot').with_ensure('absent') }
        if os_facts[:osfamily] == 'Debian'
          it { is_expected.to contain_cron('Run apt autoremove on reboot').with_ensure('absent') }
        end
      when 'windows'
        it { is_expected.to contain_scheduled_task('os_patching fact generation').with_ensure('absent') }
      end
    end
  end
end
