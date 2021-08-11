# target_info = { 'hostname' => <boot time value output from last_boot_time task> }
plan pe_patch::wait_for_reboot (
  Hash $target_info,
  Optional[Integer] $reboot_wait_time = 600,
){
  # Adapted from puppetlabs-reboot
  $targets = $target_info.keys()
  $start_time = Timestamp()
  $wait_result = without_default_logging() || {
    $reboot_wait_time.reduce({'pending' => $targets, 'ok' => []}) |$memo, $_| {
      if ($memo['pending'].empty or $memo['timed_out']) {
        break()
      }

      if $targets.size == 1 {
        $message = "Waiting for ${targets[0]} to reboot."
      } else {
        $plural = $memo['pending'].size > 1 ? {
          true => 's',
          default => '',
        }
        $message = "Waiting for ${$memo['pending'].size} node${plural} to reboot."
      }
      out::message("${message} Note that a failed pe_patch::last_boot_time task is normal while a target is in the middle of rebooting, and may be safely ignored.")
      $current_boot_time_results = run_task('pe_patch::last_boot_time', $memo['pending'], _catch_errors => true)

      $failed_results = $current_boot_time_results.filter |$current_boot_time_res| {
        # If we errored, need to check again, since it's probably still rebooting
        if !$current_boot_time_res.ok {
          true
        } else {
          # If the boot time is the same as it was before we patched,
          # we haven't rebooted yet and need to check again.
          $current_boot_time_res.message == $target_info[$current_boot_time_res.target.name]
        }
      }

      # Turn array of results into ResultSet to we can extract Targets
      $failed_targets = ResultSet($failed_results).targets.map |$t| { $t.name }
      $ok_targets = $memo['pending'] - $failed_targets

      $elapsed_time_sec = Integer(Timestamp() - $start_time)
      $timed_out = $elapsed_time_sec >= $reboot_wait_time

      if !$failed_targets.empty and !$timed_out {
        # Wait for targets to be available again before rechecking. If we end up failing
        # this wait on any of those nodes, we'll catch it in the next iteration.
        pe_patch::sleep(30)
        $remaining_time = $reboot_wait_time - $elapsed_time_sec
        wait_until_available($failed_targets, wait_time => $remaining_time, retry_interval => 1, '_catch_errors' => true)
      }

      ({
        'pending' => $failed_targets,
        'ok'      => $memo['ok'] + $ok_targets,
        'timed_out' => $timed_out,
      })
    }
  }
  return $wait_result
}