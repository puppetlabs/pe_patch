plan pe_patch::group_patching (
  String $patch_group,
  Optional[Enum['always', 'never', 'patched', 'smart']] $reboot = 'never',
  Optional[String] $yum_params = undef,
  Optional[String] $dpkg_params = undef,
  Optional[String] $zypper_params = undef,
  Optional[Integer] $patch_task_timeout = 3600,
  Optional[Integer] $health_check_runinterval = 1800,
  Optional[Integer] $reboot_wait_time = 600,
  Optional[Boolean] $security_only = false,
  Optional[Boolean] $run_health_check = true,
  Optional[Boolean] $clean_cache = false,
  Optional[Boolean] $health_check_noop = false,
  Optional[Boolean] $health_check_use_cached_catalog = false,
  Optional[Boolean] $health_check_service_enabled = true,
  Optional[Boolean] $health_check_service_running = true,
  Optional[Boolean] $sequential_patching = false,
  Optional[Pe_patch::Absolutepath] $post_reboot_scriptpath = undef,
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
        $pre_patch_run_puppet_check = run_task('enterprise_tasks::run_puppet', $puppet_healthy,
          max_timeout     => 256,
          '_catch_errors' => true)
        $patch_ready = $pre_patch_run_puppet_check.ok_set.names
        $pre_patch_puppet_run_failed = $pre_patch_run_puppet_check.error_set.names
      }
    } else {
      $patch_ready = $certnames
    }

    ### Patching, Input: $patch_ready, Output: $post_patch_ready ###
    ### Add'l result params: $patched, $not_patched, $reboot_timed_out ###
    if $patch_ready.empty {
      $post_patch_ready = []
    } else {
      # So we can detect when a node has rebooted
      $begin_boot_time_results = without_default_logging() || {
        run_task('pe_patch::last_boot_time', $patch_ready, '_catch_errors' => true)
      }

      $begin_boot_time_target_info = Hash($begin_boot_time_results.results.map |$item| {
        [$item.target.name, $item.message]
      })

      # Actually carry out the patching on all healthy nodes
      if $sequential_patching {
        $sequential_result = $patch_ready.reduce({'patched' => [], 'not_patched' => [], 'reboot_timed_out' => []}) |$memo, $node| {
          ## Patch ##
          $task_result = run_task('pe_patch::patch_server',
                                $node,
                                "Patching ${node}",
                                yum_params      => $yum_params,
                                dpkg_params     => $dpkg_params,
                                zypper_params   => $zypper_params,
                                timeout         => $patch_task_timeout,
                                reboot          => $reboot,
                                security_only   => $security_only,
                                clean_cache     => $clean_cache,
                                '_catch_errors' => true)
          if $task_result.ok {
            $memo_patched = $memo['patched'] + [$node]
            $memo_not_patched = $memo['not_patched']
          } else {
            $memo_not_patched = $memo['not_patched'] + [$node]
            $memo_patched = $memo['patched']
          }

          ## Wait for Reboot ##
          if $task_result.first.value['was_rebooted'] {
            $wait_results = run_plan('pe_patch::wait_for_reboot',
                                    target_info => { $node => $begin_boot_time_target_info[$node] },
                                    reboot_wait_time => $reboot_wait_time)
            if $wait_results['pending'].empty {
              $memo_reboot_timed_out = $memo['reboot_timed_out']
              $reboot_ok = true
            } else {
              $memo_reboot_timed_out = $memo['reboot_timed_out'] + [$node]
              $reboot_ok = false
            }
          } else {
            $memo_reboot_timed_out = $memo['reboot_timed_out']
            $reboot_ok = true
          }

          ## Post reboot script ##
          # Run the post_reboot_scriptpath, if defined. Don't fail the plan
          # if the script fails. The user will be able to see the result in
          # the console.
          if $post_reboot_scriptpath and $reboot_ok {
            run_command($post_reboot_scriptpath, $node, '_catch_errors' => true)
          }

          ({
            'patched' => $memo_patched,
            'not_patched' => $memo_not_patched,
            'reboot_timed_out' => $memo_reboot_timed_out,
          })
        }
        ## Sequential results ##
        $patched = $sequential_result['patched']
        $not_patched = $sequential_result['not_patched']
        $reboot_timed_out = $sequential_result['reboot_timed_out']
        $post_patch_ready = $patched - $reboot_timed_out
      } else {
        $patch_result = run_task('pe_patch::patch_server',
                              $patch_ready,
                              yum_params      => $yum_params,
                              dpkg_params     => $dpkg_params,
                              zypper_params   => $zypper_params,
                              timeout         => $patch_task_timeout,
                              reboot          => $reboot,
                              security_only   => $security_only,
                              clean_cache     => $clean_cache,
                              '_catch_errors' => true)

        $patched = $patch_result.ok_set.names
        $not_patched = $patch_result.error_set.names
        $rebooting_result = $patch_result.ok_set.results.filter | $result | { $result.value['was_rebooted'] }
        $rebooting = $rebooting_result.map | $result | { $result.target.name }

        ### Wait for Reboot ###
        if $rebooting.empty {
          $post_patch_ready = $patched
        } else {
          $wait_results = run_plan('pe_patch::wait_for_reboot', target_info => $begin_boot_time_target_info, reboot_wait_time => $reboot_wait_time)
          $reboot_timed_out = $wait_results['pending']
          $post_patch_ready = $patched - $reboot_timed_out
        }

        ### Post reboot script, Input: $post_patch_ready, Output: None ###
        # Run the post_reboot_scriptpath, if defined. Don't fail the plan
        # if the script fails. The user will be able to see the result in
        # the console.
        if $post_reboot_scriptpath and !$post_patch_ready.empty {
          run_command($post_reboot_scriptpath, $post_patch_ready, '_catch_errors' => true)
        }
      }
    }

    ### Post patching health check, Input: $post_patch_ready, Output: $post_patch_puppet_run_passed ###
    ### Add'l result params: $post_patch_puppet_run_failed ###
    if $post_patch_ready.empty or !$run_health_check {
      $post_patch_puppet_run_passed = $post_patch_ready
    } else {
      # Sometimes a puppet run immediately after reboot fails, so give it a bit of time.
      pe_patch::sleep(30)
      $post_puppet_check = run_task('enterprise_tasks::run_puppet', $post_patch_ready,
        max_timeout     => 256,
        '_catch_errors' => true)
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
