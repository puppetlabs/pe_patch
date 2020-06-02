require 'spec_helper'

describe 'pe_patch' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      case os_facts[:kernel]
      when 'Linux'
        let(:cache_dir) { '/var/cache/pe_patch' }
        let(:fact_cmd) { '/usr/local/bin/pe_patch_fact_generation.sh' }
      when 'windows'
        let(:cache_dir) { 'C:/ProgramData/pe_patch' }
        let(:fact_cmd) { 'C:/ProgramData/pe_patch/pe_patch_fact_generation.ps1' }
      end

      context 'when os_patching is applied' do
        let(:pre_condition) do
          <<~EOT
          class os_patching {}
          include os_patching
          EOT
        end
        it { is_expected.to contain_notify('os_patching warning') }
        it { is_expected.not_to contain_file(cache_dir) }
      end

      context 'when os_patching is not applied' do
        it { is_expected.to contain_class('pe_patch::cleanup_os_patching') }
      end

      case os_facts[:osfamily]
      when 'RedHat'
        context 'with package management enabled' do
          let(:params) {
            {
              'manage_yum_utils'           => true,
              'manage_delta_rpm'           => true,
              'manage_yum_plugin_security' => true,
            }
          }
          it { is_expected.to contain_package('deltarpm') }
          it { is_expected.to contain_package('yum-utils') }
          it { is_expected.to contain_package('yum-plugin-security') }
        end
        context 'with package management default' do
          it { is_expected.not_to contain_package('deltarpm') }
          it { is_expected.not_to contain_package('yum-utils') }
          it { is_expected.not_to contain_package('yum-plugin-security') }
        end
      end

      case os_facts[:osfamily]
      when 'Debian'
        context 'with apt_autoremove => true' do
          let(:params) { {'apt_autoremove' => true } }
          it { is_expected.to contain_cron('pe_patch - Run apt autoremove on reboot').with_ensure('present') }
        end
        context 'with apt_autoremove => default' do
          it { is_expected.to contain_cron('pe_patch - Run apt autoremove on reboot').with_ensure('absent') }
        end
      end

      context 'with block_patching_on_warnings => true' do
        let(:params) { {'block_patching_on_warnings' => true } }
        it { is_expected.to contain_file("#{cache_dir}/block_patching_on_warnings").with({
          'ensure' => 'file',
        })}
      end

      context 'with block_patching_on_warnings => false' do
        let(:params) { {'block_patching_on_warnings' => false } }
        it { is_expected.to contain_file("#{cache_dir}/block_patching_on_warnings").with({
          'ensure' => 'absent',
        })}
      end

      context 'with block_patching_on_warnings => default' do
        it { is_expected.to contain_file("#{cache_dir}/block_patching_on_warnings").with({
          'ensure' => 'absent',
        })}
      end

      context 'with reboot_override => always' do
        let(:params) { {'reboot_override' => 'always'} }
        it { is_expected.to contain_file("#{cache_dir}/reboot_override").with({
          'ensure' => 'file',
        })}
        it { is_expected.to contain_file("#{cache_dir}/reboot_override").with_content(/^always$/)}
      end

      context 'with reboot_override => never' do
        let(:params) { {'reboot_override' => 'never'} }
        it { is_expected.to contain_file("#{cache_dir}/reboot_override").with({
          'ensure' => 'file',
        })}
        it { is_expected.to contain_file("#{cache_dir}/reboot_override").with_content(/^never$/)}
      end

      context 'with reboot_override => foobar' do
        let(:params) { {'reboot_override' => 'foobar'} }
        it { is_expected.to compile.and_raise_error(/reboot_override/) }
      end

      context 'with patch_group => $#&!RYYQ!' do
        let(:params) { {'patch_group' => '(((((##(@(!$#&!RYYQ!'} }
        it { is_expected.to compile }
      end

      context 'with patch_group => Week3' do
        let(:params) { {'patch_group' => 'Week3'} }
        it { is_expected.to contain_file(cache_dir + '/patch_group').with({
          'ensure' => 'file',
        })}
        it { is_expected.to contain_file(cache_dir + '/patch_group').with_content(/^Week3$/)}
      end

      context 'with pre_patching_command => /bin/true' do
        let(:params) { {'pre_patching_command' => '/bin/true'} }
        it { is_expected.to contain_file(cache_dir + '/pre_patching_command').with({
          'ensure' => 'file',
        })}
        it { is_expected.to contain_file(cache_dir + '/pre_patching_command').with_content(/^\/bin\/true$/)}
      end

      context 'with pre_patching_command => undef' do
        let(:params) { {'pre_patching_command' => :undef } }
        it { is_expected.to contain_file(cache_dir + '/pre_patching_command').with({
          'ensure' => 'absent',
        })}
      end

      context 'with blackout window set' do
        let(:params) {
          {
            'blackout_windows' => { 'End of year change freeze': { 'start': '2018-12-15T00:00:00+10:00', 'end': '2019-01-15T23:59:59+10:00' } }
          }
        }
        it { is_expected.to contain_file(cache_dir + '/blackout_windows').with({
          'ensure' => 'file',
        })}
        it { is_expected.to contain_file(cache_dir + '/blackout_windows').with_content(/End of year change/)}
      end

      it { is_expected.to compile }
      it { is_expected.to compile.with_all_deps }
      it { is_expected.to contain_class('pe_patch') }
      it { is_expected.to contain_file(cache_dir).with({
        'ensure' => 'directory',
      })}

      it { is_expected.to contain_file(cache_dir + '/blackout_windows').with({
        'ensure' => 'absent',
      })}

      it { is_expected.to contain_file(cache_dir + '/patch_group').with({
        'ensure' => 'absent',
      })}

      it { is_expected.to contain_file(cache_dir + '/reboot_override').with({
        'ensure' => 'file',
      })}

      it { is_expected.to contain_file(cache_dir + '/reboot_override').with_content(/^default$/)}

      it { is_expected.to contain_file(fact_cmd).with({
        'ensure' => 'file',
      })}

      case os_facts[:kernel]
      when 'Linux'
        it { is_expected.to contain_cron('pe_patch - Cache patching data').with_ensure('present') }
        it { is_expected.to contain_cron('pe_patch - Cache patching data at reboot').with_ensure('present') }
        it { is_expected.to contain_exec('pe_patch::exec::fact').that_requires(
          'File[' + cache_dir + '/reboot_override]',
        )}
      when 'windows'
        it { is_expected.to contain_scheduled_task('pe_patch fact generation').with_ensure('present') }
      end
      it { is_expected.to contain_exec('pe_patch::exec::fact').with_timeout(900) }
      it { is_expected.to contain_exec('pe_patch::exec::fact_upload') }

      context 'block on warnings' do
        let(:params) { { 'block_patching_on_warnings' => true } }
        it { is_expected.to contain_file(cache_dir + '/block_patching_on_warnings') }
      end

      context 'debian reboot' do
        let(:params) { { 'apt_autoremove' => true } }
        case os_facts[:osfamily]
        when 'Debian'
          it { is_expected.to contain_cron('pe_patch - Run apt autoremove on reboot').with_ensure('present') }
        end
      end

      context 'purge module' do
        let(:params) { {'ensure' => 'absent'} }
        it { is_expected.to contain_file(cache_dir).with({
          'ensure' => 'absent',
        })}
      end
    end
  end
end
