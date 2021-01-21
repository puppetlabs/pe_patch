plan pe_patch::group_patching (
  String $patch_group,
  Boolean $security_only = false,
  Enum['always', 'never', 'patched', 'smart'] $reboot = 'patched',
  Integer $reboot_wait_time = 300,
  Boolean $run_health_check = true,
  Optional[Integer] $health_check_runinterval = 1800,
  Optional[Boolean] $health_check_noop = false,
  Optional[Boolean] $health_check_use_cached_catalog = false,
  Optional[Boolean] $health_check_service_enabled = true,
  Optional[Boolean] $health_check_service_running = true,
){
  # Query PuppetDB to find nodes that have the patch group,
  # are not blocked, and have patches to apply.
  $all_nodes = puppetdb_query("inventory[certname] { facts.pe_patch.patch_group = '${patch_group}'}")
  $filtered_nodes = puppetdb_query("inventory[certname] { facts.pe_patch.patch_group = '${patch_group}' and facts.pe_patch.blocked = false and facts.pe_patch.package_update_count > 0}")

  # Transform the query output into Targetspec
  $full_list = $all_nodes.map | $r | { $r['certname'] }
  $certnames = $filtered_nodes.map | $r | { $r['certname'] }
  $targets = get_targets($certnames)

  unless $targets.empty {
    ### Health Check, Input: $targets, Output: $patch_ready ###
    ### Add'l result params: $puppet_not_healthy, $pre_patch_puppet_run_failed ###
    if $run_health_check {
      # Check the health of the puppet agent on all nodes
      # Ensure puppet configuration is as expected, agent hasn't been disabled
      # with puppet agent --disable, puppet ssl verify passes, the puppet
      # service is in the right state, all servers are reachable, and the
      # last puppet run didn't have failures.
      $agent_health = run_task('pe_patch::agent_health', $targets,
        target_runinterval              => $health_check_runinterval,
        target_noop_state               => $health_check_noop,
        target_use_cached_catalog_state => $health_check_use_cached_catalog,
        target_service_enabled          => $health_check_service_enabled,
        target_service_running          => $health_check_service_running,
        '_catch_errors'                 => true)

      # Pull out list of those that are ok/in error
      $puppet_healthy = $agent_health.ok_set.names
      $puppet_not_healthy = $agent_health.error_set.results.map | $error | { $error.error.details }

      if $puppet_healthy.empty {
        $patch_ready = []
      } else {
        $pre_patch_run_puppet_check = run_task('enterprise_tasks::run_puppet', $puppet_healthy, '_catch_errors' => true)
        $patch_ready = $pre_patch_run_puppet_check.ok_set.names
        $pre_patch_puppet_run_failed = $pre_patch_run_puppet_check.error_set.names
      }
    } else {
      $patch_ready = $certnames
    }

    ### Patching, Input: $patch_ready, Output: $post_patch_ready ###
    ### Add'l result params: $not_patched, $reboot_timed_out ###
    if $patch_ready.empty {
      $post_patch_ready = []
    } else {
      # So we can detect when a node has rebooted
      $begin_boot_time_results = without_default_logging() || {
        run_task('pe_patch::last_boot_time', $patch_ready)
      }

      # Actually carry out the patching on all healthy nodes
      $patch_result = run_task('pe_patch::patch_server',
                            $patch_ready,
                            reboot          => $reboot,
                            security_only   => $security_only,
                            '_catch_errors' => true)

      # Pull out list of those that are ok/in error
      $patched = $patch_result.ok_set.names
      $not_patched = $patch_result.error_set.names
      $rebooting_result = $patch_result.ok_set.results.filter | $result | { $result.value['was_rebooted'] }
      $rebooting = $rebooting_result.map | $result | { $result.target.name }

      ### Wait for Reboot ###
      if $rebooting.empty {
        $post_patch_ready = $patched
      } else {
        # Adapted from puppetlabs-reboot
        $start_time = Timestamp()
        $wait_results = without_default_logging() || {
          $reboot_wait_time.reduce({'pending' => $rebooting, 'ok' => []}) |$memo, $_| {
            if ($memo['pending'].empty or $memo['timed_out']) {
              break()
            }

            out::message("Waiting for ${$memo['pending'].size} node(s) to reboot. Note that a failed pe_patch::last_boot_time task is normal while a target is in the middle of rebooting, and may be safely ignored.")
            $current_boot_time_results = run_task('pe_patch::last_boot_time', $memo['pending'], _catch_errors => true)

            $failed_results = $current_boot_time_results.filter |$current_boot_time_res| {
              # If we errored, need to check again, since it's probably still rebooting
              if !$current_boot_time_res.ok {
                true
              } else {
                # If the boot time is the same as it was before we patched,
                # we haven't rebooted yet and need to check again.
                $target_name = $current_boot_time_res.target.name
                $begin_boot_time_res = $begin_boot_time_results.find($target_name)
                $current_boot_time_res.value == $begin_boot_time_res.value
              }
            }

            # Turn array of results into ResultSet to we can extract Targets
            $failed_targets = ResultSet($failed_results).targets.map |$t| { $t.name }
            $ok_targets = $memo['pending'] - $failed_targets

            $elapsed_time_sec = Integer(Timestamp() - $start_time)
            $timed_out = $elapsed_time_sec >= $reboot_wait_time

            if !$failed_targets.empty and !$timed_out {
              # Wait for targets to be available again before rechecking
              pe_patch::sleep(30)
              $remaining_time = $reboot_wait_time - $elapsed_time_sec
              wait_until_available($failed_targets, wait_time => $remaining_time, retry_interval => 1)
            }

            ({
              'pending' => $failed_targets,
              'ok'      => $memo['ok'] + $ok_targets,
              'timed_out' => $timed_out,
            })
          }
        }
        $reboot_timed_out = $wait_results['pending']
        $post_patch_ready = $patched.filter |$patched_node| { !$reboot_timed_out.any |$timed_out| { $timed_out == $patched_node } }
        $test = $patched - $reboot_timed_out
      }
    }

    ### Post patching health check, Input: $post_patch_ready, Output: $post_patch_puppet_run_passed ###
    ### Add'l result params: $post_patch_puppet_run_failed ###
    if $post_patch_ready.empty or !$run_health_check {
      $post_patch_puppet_run_passed = $post_patch_ready
    } else {
      # Sometimes a puppet run immediately after reboot fails, so give it a bit of time.
      pe_patch::sleep(30)
      $post_puppet_check = run_task('enterprise_tasks::run_puppet', $post_patch_ready, '_catch_errors' => true)
      $post_patch_puppet_run_passed = $post_puppet_check.ok_set.names
      $post_patch_puppet_run_failed = $post_puppet_check.error_set.names
    }
  }

  ### Defaults ###
  # Note: $patch_group, $full_list, and $targets are always defined,
  # so no need to set a default value here.
  $puppet_not_healthy_result = defined('$puppet_not_healthy') ? {
    true    => $puppet_not_healthy,
    default => [],
  }

  $pre_patch_puppet_run_failed_result = defined('$pre_patch_puppet_run_failed') ? {
    true    => $pre_patch_puppet_run_failed,
    default => [],
  }

  $patched_result = defined('$patched') ? {
    true    => $patched,
    default => [],
  }

  $not_patched_result = defined('$not_patched') ? {
    true    => $not_patched,
    default => [],
  }

  $post_patch_puppet_run_failed_result = defined('$post_patch_puppet_run_failed') ? {
    true    => $post_patch_puppet_run_failed,
    default => [],
  }

  $reboot_timed_out_result = defined('$reboot_timed_out') ? {
    true    => $reboot_timed_out,
    default => [],
  }

  # Output the results
  return({
    'patch_group'                  => $patch_group,
    'all_nodes_in_group'           => $full_list,
    'patchable_nodes'              => $targets,
    'puppet_health_check_failed'   => $puppet_not_healthy_result,
    'pre_patch_puppet_run_failed'  => $pre_patch_puppet_run_failed_result,
    'patching_failed'              => $not_patched_result,
    'post_patch_puppet_run_failed' => $post_patch_puppet_run_failed_result,
    'reboot_timed_out'             => $reboot_timed_out_result,
    'nodes_patched'                => $patched_result,
    'counts'                       => {
      'all_nodes_in_group_count'        => $full_list.length,
      'patchable_nodes_count'           => $targets.length,
      'puppet_health_check_failed'      => $puppet_not_healthy_result.length,
      'pre_patch_puppet_run_failed'     => $pre_patch_puppet_run_failed_result.length,
      'patching_failed'                 => $not_patched_result.length,
      'post_patch_puppet_run_failed'    => $post_patch_puppet_run_failed_result.length,
      'reboot_timed_out'                => $reboot_timed_out_result.length,
      'nodes_patched'                   => $patched_result.length,
    }
  })
}