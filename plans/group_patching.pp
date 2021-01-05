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
    } else {
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
        # It takes a minute for the reboot to actually start, so wait a bit
        # unless reboot == never. This is imperfect, as it may actually
        # be installing updates as it's restarting and remain responsive
        # to wait_until_available. In the future, we should make the patch_server
        # task handle waiting for the node to reboot, or use the puppetlabs/reboot
        # module.
        if $rebooting.empty {
          $to_post_puppet_check = $patched
        } else {
          #sleep(30)
          $reboot_check = wait_until_available($rebooting, wait_time => $reboot_wait_time)
          $to_post_puppet_check = $reboot_check.ok_set.names
          $not_rebooted = $reboot_check.error_set.names # Not using this currently
        }

        $post_puppet_check = run_task('enterprise_tasks::run_puppet', $to_post_puppet_check, '_catch_errors' => true)
        $check_passed = $post_puppet_check.ok_set.names
        $check_failed = $post_puppet_check.error_set.names
      } else {
        $check_passed = $patched
        $check_failed = []
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
    'nodes_patched'              => $check_passed,
    'counts'                     => {
      'all_nodes_in_group_count'   => $full_list.length,
      'patchable_nodes_count'      => $targets.length,
      'puppet_health_check_failed' => $puppet_not_healthy.length,
      'node_health_check_failed'   => $node_not_healthy.length,
      'patching_failed'            => $not_patched.length,
      'post_check_failed'          => $check_failed.length,
      'nodes_patched'              => $check_passed.length,
    }
  })
}