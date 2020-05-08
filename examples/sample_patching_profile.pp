# lint:ignore:autoloader_layout
class sample_patching_profile (
  $patch_group      = undef,
  $blackout_windows = undef,
  $reboot_override  = undef,
){
# lint:endignore
  # Pull any blackout windows out of hiera
  $hiera_blackout_windows = lookup('profiles::soe::patching::blackout_windows',Hash,hash,{})

  # Merge the blackout windows from the parameter and hiera
  $full_blackout_windows = $hiera_blackout_windows + $blackout_windows

  # Call the pe_patch class to set everything up
  class { 'pe_patch':
    patch_group      => $patch_group,
    reboot_override  => $reboot_override,
    blackout_windows => $full_blackout_windows,
  }
}
