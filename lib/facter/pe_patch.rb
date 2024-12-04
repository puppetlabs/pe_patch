# Ensure that this fact does not try to be loaded
# on old (pre v.2) versions of facter as it uses
# aggregate facts
if Facter.value(:facterversion).split('.')[0].to_i < 2
  Facter.add('pe_patch') do
    setcode do
      'not valid on legacy facter versions'
    end
  end
else
  Facter.add('pe_patch', :type => :aggregate) do
    confine { Facter.value(:kernel) == 'windows' || Facter.value(:kernel) == 'Linux' }
    require 'time'
    now = Time.now.iso8601
    warnings = {}
    blocked = false
    blocked_reasons = []

    if Facter.value(:kernel) == 'Linux'
      pe_patch_dir = '/opt/puppetlabs/pe_patch'
    elsif Facter.value(:kernel) == 'windows'
      pe_patch_dir = 'C:\ProgramData\PuppetLabs\pe_patch'
    end

    chunk(:updates) do
      data = {}
      updatelist = []
      updatefile = pe_patch_dir + '/package_updates'
      if File.file?(updatefile)
        if (Time.now - File.mtime(updatefile)) / (24 * 3600) > 10
          warnings['update_file_time'] = 'Update file has not been updated in 10 days'
        end

        updates = File.open(updatefile, 'r').read
        updates.each_line do |line|
          next unless line =~ /[A-Za-z0-9]+/
          next if line =~ /^#|^$/
          line.sub! 'Title : ', ''
          updatelist.push line.chomp
        end
      else
        warnings['update_file'] = 'Update file not found, update information invalid'
      end
      data['package_updates'] = updatelist
      data['package_update_count'] = updatelist.count
      data
    end

    chunk(:updates_with_version) do
      data = {}
      updateset = {}
      updatefile = pe_patch_dir + '/package_updates_with_version'
      if File.file?(updatefile)
        if (Time.now - File.mtime(updatefile)) / (24 * 3600) > 10
          warnings['update_file_time'] = 'Update version file has not been updated in 10 days'
        end

        updates = File.open(updatefile, 'r').read
        updates.each_line do |line|
          next unless line =~ /[A-Za-z0-9]+/
          next if line =~ /^#|^$/
          line.sub! 'Title : ', ''
          pkg = line.split(' , ')
          updateset[pkg[0]] = pkg[1]
        end
      else
        warnings['update_file_with_version'] = 'Update version file not found, update information invalid'
      end
      data['package_updates_with_version'] = updateset
      data
    end

    chunk(:kb_updates) do
      data = {}
      kblist = []
      kbfile = pe_patch_dir + '/missing_update_kbs'
      if File.file?(kbfile) && !File.zero?(kbfile)
        kbs = File.open(kbfile, 'r').read
        kbs.each_line do |line|
          kblist.push line.chomp
        end
      end
      data['missing_update_kbs'] = kblist
      data
    end

    chunk(:kb_secupdates) do
      data = {}
      kblist = []
      kbfile = pe_patch_dir + '/missing_security_kbs'
      if File.file?(kbfile) && !File.zero?(kbfile)
        kbs = File.open(kbfile, 'r').read
        kbs.each_line do |line|
          kblist.push line.chomp
        end
      end
      data['missing_security_kbs'] = kblist
      data
    end

    chunk(:secupdates) do
      data = {}
      secupdatelist = []
      secupdatefile = pe_patch_dir + '/security_package_updates'
      if File.file?(secupdatefile)
        if (Time.now - File.mtime(secupdatefile)) / (24 * 3600) > 10
          warnings['sec_update_file_time'] = 'Security update file has not been updated in 10 days'
        end
        secupdates = File.open(secupdatefile, 'r').read
        secupdates.each_line do |line|
          next if line.empty?
          next if line =~ /^#|^$/
          secupdatelist.push line.chomp
        end
      else
        warnings['security_update_file'] = 'Security update file not found, update information invalid'
      end
      data['security_package_updates'] = secupdatelist
      data['security_package_update_count'] = secupdatelist.count
      data
    end

    chunk(:secupdates) do
      data = {}
      secupdatehash = {}
      secupdatefile = pe_patch_dir + '/security_package_updates_with_version'
      if File.file?(secupdatefile)
        if (Time.now - File.mtime(secupdatefile)) / (24 * 3600) > 10
          warnings['sec_update_file_time'] = 'Security update version file has not been updated in 10 days'
        end
        secupdates = File.open(secupdatefile, 'r').read
        secupdates.each_line do |line|
          next if line.empty?
          next if line =~ /^#|^$/
          pkg = line.split(' , ')
          secupdatehash[pkg[0]] = pkg[1]
        end
      else
        warnings['security_update_file'] = 'Security update version file not found, update information invalid'
      end
      data['security_package_updates_with_version'] = secupdatehash
      data
    end

    chunk(:blackouts) do
      data = {}
      arraydata = {}
      blackoutfile = pe_patch_dir + '/blackout_windows'
      if File.file?(blackoutfile)
        blackouts = File.open(blackoutfile, 'r').read
        blackouts.each_line do |line|
          next if line.empty?
          next if line =~ /^#|^$/
          matchdata = line.match(/^([\w ]*),(\d{,4}-\d{1,2}-\d{1,2}T\d{,2}:?\d{,2}:?\d{,2}[-\+]\d{,2}:?\d{,2}),(\d{,4}-\d{1,2}-\d{1,2}T\d{,2}:?\d{,2}:?\d{,2}[-\+]\d{,2}:?\d{,2})$/)
          if matchdata
            arraydata[matchdata[1]] = {} unless arraydata[matchdata[1]]
            if matchdata[2] > matchdata[3]
              arraydata[matchdata[1]]['start'] = 'Start date after end date'
              arraydata[matchdata[1]]['end'] = 'Start date after end date'
              warnings['blackouts'] = matchdata[0] + ' : Start data after end date'
            else
              arraydata[matchdata[1]]['start'] = matchdata[2]
              arraydata[matchdata[1]]['end'] = matchdata[3]
            end

            if (matchdata[2]..matchdata[3]).cover?(now)
              blocked = true
              blocked_reasons.push matchdata[1]
            end
          else
            warnings['blackouts'] = "Invalid blackout entry : #{line}"
            blocked = true
            blocked_reasons.push "Invalid blackout entry : #{line}"
          end
        end
      end
      data['blackouts'] = arraydata
      data
    end

    # Are there any pinned/version locked packages?
    chunk(:pinned) do
      data = {}
      pinnedpkgs = []
      mismatchpinnedpackagefile = pe_patch_dir + '/mismatched_version_locked_packages'
      pinnedpackagefile = pe_patch_dir + '/os_version_locked_packages'
      if File.file?(pinnedpackagefile)
        pinnedfile = File.open(pinnedpackagefile, 'r').read.chomp
        pinnedfile.each_line do |line|
          pinnedpkgs.push line.chomp
        end
      end
      if File.file?(mismatchpinnedpackagefile) && !File.zero?(mismatchpinnedpackagefile)
        warnings['version_specified_but_not_locked_packages'] = []
        mismatchfile = File.open(mismatchpinnedpackagefile, 'r').read
        mismatchfile.each_line do |line|
          warnings['version_specified_but_not_locked_packages'].push line.chomp
        end
      end
      data['pinned_packages'] = pinnedpkgs
      data
    end

    # History info
    chunk(:history) do
      data = {}
      patchhistoryfile = pe_patch_dir + '/run_history'
      data['last_run'] = {}
      if File.file?(patchhistoryfile)
        historyfile = File.open(patchhistoryfile, 'r').to_a
        line = historyfile.last.chomp
        matchdata = line.split('|')
        if matchdata[1]
          data['last_run']['date'] = matchdata[0]
          data['last_run']['message'] = matchdata[1]
          data['last_run']['return_code'] = matchdata[2]
          data['last_run']['post_reboot'] = matchdata[3]
          data['last_run']['security_only'] = matchdata[4]
          data['last_run']['job_id'] = matchdata[5]
          data['last_run']['was_rebooted'] = matchdata[6] if matchdata[6]
        end
      end
      data
    end

    # Patch group
    chunk(:patch_group) do
      data = {}
      patchgroupfile = pe_patch_dir + '/patch_group'
      if File.file?(patchgroupfile)
        patchgroup = File.open(patchgroupfile, 'r').to_a
        line = patchgroup.last
        matchdata = line.match(/^(.*)$/)
        if matchdata[0]
          data['patch_group'] = matchdata[0]
        end
      else
        data['patch_group'] = ''
      end
      data
    end

    # Reboot override
    chunk(:reboot_override) do
      rebootfile = pe_patch_dir + '/reboot_override'
      data = {}
      if File.file?(rebootfile)
        rebootoverride = File.open(rebootfile, 'r').to_a
        data['reboot_override'] = case rebootoverride.last
                                  when /^always$/
                                    'always'
                                  when /^[Tt]rue$/
                                    'always'
                                  when /^[Ff]alse$/
                                    'never'
                                  when /^never$/
                                    'never'
                                  when /^patched$/
                                    'patched'
                                  when /^smart$/
                                    'smart'
                                  else
                                    'default'
                                  end
      else
        data['reboot_override'] = 'default'
      end
      data
    end

    # Reboot or restarts required?
    chunk(:reboot_required) do
      data = {}
      data['reboots'] = {}
      reboot_required_file = pe_patch_dir + '/reboot_required'
      if File.file?(reboot_required_file)
        if (Time.now - File.mtime(reboot_required_file)) / (24 * 3600) > 10
          warnings['reboot_required_file_time'] = 'Reboot required file has not been updated in 10 days'
        end
        reboot_required_fh = File.open(reboot_required_file, 'r').to_a
        data['reboots']['reboot_required'] = case reboot_required_fh.last
                                             when /^[Tt]rue$/
                                               true
                                             when /^[Ff]alse$/
                                               false
                                             else
                                               ''
                                             end
      else
        data['reboots']['reboot_required'] = 'unknown'
      end
      app_restart_file = pe_patch_dir + '/apps_to_restart'
      if File.file?(app_restart_file)
        app_restart_fh = File.open(app_restart_file, 'r').to_a
        data['reboots']['apps_needing_restart'] = {}
        app_restart_fh.each do |line|
          line.chomp!
          key_value = line.split(' : ')
          data['reboots']['apps_needing_restart'][key_value[0]] = key_value[1]
        end
        data['reboots']['app_restart_required'] = if data['reboots']['apps_needing_restart'].empty?
                                                    false
                                                  else
                                                    true
                                                  end
      end
      data
    end

    # Should we patch if there are warnings?
    chunk(:pre_patching_scriptpath) do
      data = {}
      pre_patching_scriptpath = pe_patch_dir + '/pre_patching_scriptpath'
      if File.file?(pre_patching_scriptpath) && !File.empty?(pre_patching_scriptpath)
        command = File.open(pre_patching_scriptpath, 'r').to_a
        line = command.last
        matchdata = line.match(/^(.*)$/)
        if matchdata[0]
          if File.file?(matchdata[0])
            if File.executable?(matchdata[0])
              data['pre_patching_scriptpath'] = matchdata[0]
            else
              warnings['blackouts'] = "pre_patching_scriptpath not executable : #{matchdata[0]}"
              blocked = true
              blocked_reasons.push "pre_patching_scriptpath not executable : #{matchdata[0]}"
            end
          else
            warnings['pre_patching_scriptpath'] = "Invalid pre_patching_scriptpath entry : #{matchdata[0]}.  File must exist and be a single command with no arguments"
            blocked = true
            blocked_reasons.push "Invalid pre_patching_scriptpath entry : #{matchdata[0]}.  File must exist and be a single command with no arguments"
          end
        end
      end
      data
    end

    chunk(:post_patching_scriptpath) do
      data = {}
      post_patching_scriptpath = pe_patch_dir + '/post_patching_scriptpath'
      if File.file?(post_patching_scriptpath) && !File.empty?(post_patching_scriptpath)
        command = File.open(post_patching_scriptpath, 'r').to_a
        line = command.last
        matchdata = line.match(/^(.*)$/)
        if matchdata[0]
          if File.file?(matchdata[0])
            if File.executable?(matchdata[0])
              data['post_patching_scriptpath'] = matchdata[0]
            else
              warnings['blackouts'] = "post_patching_scriptpath not executable : #{matchdata[0]}"
              blocked = true
              blocked_reasons.push "post_patching_scriptpath not executable : #{matchdata[0]}"
            end
          else
            warnings['post_patching_scriptpath'] = "Invalid post_patching_scriptpath entry : #{matchdata[0]}.  File must exist and be a single command with no arguments"
            blocked = true
            blocked_reasons.push "Invalid post_patching_scriptpath entry : #{matchdata[0]}.  File must exist and be a single command with no arguments"
          end
        end
      end
      data
    end

    # Should we patch if there are warnings?
    chunk(:block_patching_on_warnings) do
      data = {}
      abort_on_warningsfile = pe_patch_dir + '/block_patching_on_warnings'
      if File.file?(abort_on_warningsfile)
        data['block_patching_on_warnings'] = 'true'
        unless warnings.empty?
          blocked = true
          blocked_reasons.push warnings
        end
      else
        data['block_patching_on_warnings'] = 'false'
        data['warnings'] = warnings
      end
      data['blocked'] = blocked
      data['blocked_reasons'] = blocked_reasons
      data
    end
  end
end
