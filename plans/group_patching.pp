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
  Optional[Variant[Boolean,Enum['running', 'stopped']]] $health_check_service_running = 'running',
){
  # Query PuppetDB to find nodes that have the patch group,
  # are not blocked, and have patches to apply.
  $all_nodes = puppetdb_query("inventory[certname] { facts.pe_patch.patch_group = '${patch_group}'}")
  $filtered_nodes = puppetdb_query("inventory[certname] { facts.pe_patch.patch_group = '${patch_group}' and facts.pe_patch.blocked = false and facts.pe_patch.package_update_count > 0}")

  # Transform the query output into Targetspec
  $full_list = $all_nodes.map | $r | { $r['certname'] }
  $certnames = $filtered_nodes.map | $r | { $r['certname'] }
  $targets = get_targets($certnames)

  # Start the work
  if $targets.empty {
    # Set the return variables to empty as there is nothing to patch
    $puppet_not_healthy = []
    $node_not_healthy   = []
    $not_patched        = []
    $check_failed       = []
    $check_passed       = []
    $reboot_timed_out   = []
  } else {
    # Check the health of the puppet agent on all nodes
    # Ensures puppet configuration is as expected, agent hasn't been disabled with puppet agent --disable,
    # puppet ssl verify passes, the puppet service is in the right state, all servers are reachable,
    # and the last puppet run didn't have failures.
    if $run_health_check {
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

      # Proceed if there are healthy agents
      if $puppet_healthy.empty {
        $node_healthy = []
        $node_not_healthy = []
      } else {
        # Verify we can do a puppet run with no errors
        $health_check = run_task('enterprise_tasks::run_puppet', $puppet_healthy, '_catch_errors' => true)

        # Pull out list of those that are ok/in error
        $node_healthy = $health_check.ok_set.names
        $node_not_healthy = $health_check.error_set.names
      }
    } else {
      $node_healthy = $certnames
      $puppet_not_healthy = []
      $node_not_healthy = []
    }

    # Proceed if there are healthy nodes
    if $node_healthy.empty {
      $not_patched        = []
      $check_failed       = []
      $check_passed       = []
      $reboot_timed_out   = []
    } else {
      # So we can detect when a node has rebooted
      $begin_boot_time_results = without_default_logging() || {
        run_task('pe_patch::last_boot_time', $node_healthy)
      }

      # Actually carry out the patching on all healthy nodes
      $to_patch = run_task('pe_patch::patch_server',
                            $node_healthy,
                            reboot          => $reboot,
                            security_only   => $security_only,
                            '_catch_errors' => true)

      # Pull out list of those that are ok/in error
      $patched = $to_patch.ok_set.names
      $not_patched = $to_patch.error_set.names
      $rebooting_results = $to_patch.ok_set.results.filter | $result | { $result.value['was_rebooted'] }
      $rebooting = $rebooting_results.map | $result | { $result.target }

      if $run_health_check {
        # Wait until the nodes are back up
        if $rebooting.empty {
          $to_post_puppet_check = $patched
          $reboot_timed_out = []
        } else {
          # Adapted from puppetlabs-reboot
          $start_time = Timestamp()
          $wait_results = without_default_logging() || {
            $reboot_wait_time.reduce({'pending' => $rebooting, 'ok' => []}) |$memo, $_| {
              if ($memo['pending'].empty() or $memo['timed_out']) {
                break()
              }

              out::message("Waiting for ${$memo['pending'].size()} node(s) to reboot. Note that a failed pe_patch::last_boot_time task is normal while a target is in the middle of rebooting, and may be safely ignored.")
              $current_boot_time_results = run_task('pe_patch::last_boot_time', $memo['pending'], _catch_errors => true)

              $failed_results = $current_boot_time_results.filter |$current_boot_time_res| {
                # If we errored, need to check again, since it's probably still rebooting
                if !$current_boot_time_res.ok() {
                  true
                } else {
                  # If the boot time is the same as it was before we patched,
                  # we haven't rebooted yet and need to check again.
                  $target_name = $current_boot_time_res.target().name()
                  $begin_boot_time_res = $begin_boot_time_results.find($target_name)
                  $current_boot_time_res.value() == $begin_boot_time_res.value()
                }
              }

              # Turn array of results into ResultSet to we can extract Targets
              $failed_targets = ResultSet($failed_results).targets()
              $ok_targets = $memo['pending'] - $failed_targets

              $elapsed_time_sec = Integer(Timestamp() - $start_time)
              $timed_out = $elapsed_time_sec >= $reboot_wait_time

              if !$failed_targets.empty() and !$timed_out {
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
          $to_post_puppet_check = $wait_results['ok']
          $reboot_timed_out = $wait_results['pending']
        }

        if $to_post_puppet_check.empty {
          $check_passed = []
          $check_failed = []
        } else {
          # Sometimes a puppet run immediately after reboot fails, so give it a bit of time.
          pe_patch::sleep(30)
          $post_puppet_check = run_task('enterprise_tasks::run_puppet', $to_post_puppet_check, '_catch_errors' => true)
          $check_passed = $post_puppet_check.ok_set.names
          $check_failed = $post_puppet_check.error_set.names
        }
      } else {
        $check_passed = []
        $check_failed = []
        $reboot_timed_out = []
      }
    }
  }

  # Output the results
  return({
    'patch_group'                => $patch_group,
    'all_nodes_in_group'         => $full_list,
    'patchable_nodes'            => $targets,
    'puppet_health_check_failed' => $puppet_not_healthy,
    'node_health_check_failed'   => $node_not_healthy,
    'patching_failed'            => $not_patched,
    'post_check_failed'          => $check_failed,
    'reboot_timed_out'           => $reboot_timed_out,
    'nodes_patched'              => $patched,
    'counts'                     => {
      'all_nodes_in_group_count'   => $full_list.length,
      'patchable_nodes_count'      => $targets.length,
      'puppet_health_check_failed' => $puppet_not_healthy.length,
      'node_health_check_failed'   => $node_not_healthy.length,
      'patching_failed'            => $not_patched.length,
      'post_check_failed'          => $check_failed.length,
      'reboot_timed_out'           => $reboot_timed_out.length,
      'nodes_patched'              => $patched.length,
    }
  })
}