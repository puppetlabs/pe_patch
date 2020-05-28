# Clean up any remnants of the os_patching module on the node
#
# When a node has the os_patching class removed without first setting
# os_patching::ensure == absent, it does not remove
# the various things that class lays down (cron job, cache dir, etc.).
# This removes those artifacts so only pe_patch artifacts remain.
class pe_patch::cleanup_os_patching {
  case $::kernel {
    'Linux': {
      $cache_dir           = '/var/cache/os_patching'
      $fact_dir            = '/usr/local/bin'
      $fact_file           = 'os_patching_fact_generation.sh'
    }
    'windows': {
      $cache_dir           = 'C:/ProgramData/os_patching'
      $fact_dir            = $cache_dir
      $fact_file           = 'os_patching_fact_generation.ps1'
    }
    default: { fail("Unsupported OS : ${facts['kernel']}") }
  }

  $fact_cmd = "${fact_dir}/${fact_file}"

  file { $fact_cmd:
    ensure => absent,
    before => File[$cache_dir],
  }

  file { $cache_dir:
    ensure => absent,
    force  => true,
  }

  case $::kernel {
    'Linux': {
      cron { 'Cache patching data':
        ensure  => absent,
      }

      cron { 'Cache patching data at reboot':
        ensure  => absent,
      }

      if $facts['os']['family'] == 'Debian' {
        cron { 'Run apt autoremove on reboot':
          ensure  => absent,
        }
      }
    }
    'windows': {
      scheduled_task { 'os_patching fact generation':
        ensure => absent,
      }
    }
    default: { fail('Unsupported OS') }
  }
}