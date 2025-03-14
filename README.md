# pe_patch

This repo is a fork of albatrossflavour/puppet_os_patching. Note that many of the links and some docs may refer to os_patching and may not reflect the latest features of pe_patch.

This module contains a set of tasks and custom facts to allow the automation of and reporting on operating system patching. Currently patching works on Linux (Redhat, Suse and Debian derivatives) and Windows (Server 2008 through to 2019 have been tested).

Under the hood it uses the OS level tools or APIs to carry out the actual patching.  That does mean that you need to be sure that your nodes are ABLE to search for their updates using the native tool - e.g. You still need to manage the configuration of YUM, APT, Zypper or Windows Update.

Note - Windows systems require at least PowerShell version 3.0. If you are intending to update an unpatched Windows system prior to Server 2012, you will need to update PowerShell first.

[The wiki](https://github.com/albatrossflavour/puppet_os_patching/wiki/Background) contains some useful background information on the module and how it works.

## Description

Puppet Enterprise tasks and Bolt have opened up methods to integrate operating system level patching into the puppet workflow.  Providing automation of patch execution through tasks and the robust reporting of state through custom facts and PuppetDB.

If you're looking for a simple way to report on your OS patch levels, this module will show all updates which are outstanding, including which are related to security updates.  Do you want to enable self-service patching?  This module will use Puppet's RBAC and orchestration and task execution facilities to give you that power.

It also uses security metadata (where available) to determine if there are security updates.  On Redhat, this is provided from Redhat as additional metadata in YUM.  On Debian, checks are done for which repo the updates are coming from.  On Windows, this information is provided by default. There is a parameter to the pe_patch::patch_server task to only apply security updates.

Blackout windows enable the support for time based change freezes where no patching can happen.  There can be multiple windows defined and each which will automatically expire after reaching the defined end date.

## Setup

### What pe_patch affects

The module provides an additional fact (`pe_patch`) and has a task to allow the patching of a server.  When the `pe_patch` manifest is added to a node it installs a script and cron job (Linux) or scheduled task (Windows) to check for available updates and generate cache data used by the `pe_patch` fact.

### Beginning with pe_patch

Install the module using the Puppetfile, include it on your nodes and then use the provided tasks to carry out patching.

## Usage

### Manifest
Include the module:
```puppet
include pe_patch
```

More advanced usage:
```puppet
class { 'pe_patch':
  patch_group      => 'Week3',
  blackout_windows => { 'End of year change freeze':
    {
      'start': '2018-12-15T00:00:00+1000',
      'end':   '2019-01-15T23:59:59+1000',
    }
  },
}
```

In that example, the node is assigned to a "patch group", will be forced to reboot regardless of the setting specified in the task and has a blackout window defined for the period of 2018-12-15 - 2019-01-15, during which time no patching through the task can be carried out.

### Task
Run a basic patching task from the command line:
```bash
pe_patch::patch_server - Carry out OS patching on the server, optionally including a reboot and/or only applying security related updates

USAGE:
$ puppet task run pe_patch::patch_server [dpkg_params=<value>] [reboot=<value>] [security_only=<value>] [timeout=<value>] [yum_params=<value>] [package_list=[<value>]] <[--nodes, -n <node-names>] | [--query, -q <'query'>]>

PARAMETERS:
- dpkg_params : Optional[String]
    Any additional parameters to include in the dpkg command
- reboot : Optional[Variant[Boolean, Enum['always', 'never', 'patched', 'smart']]]
    Should the server reboot after patching has been applied? (Defaults to "never")
- security_only : Optional[Boolean]
    Limit patches to those tagged as security related? (Defaults to false)
- timeout : Optional[Integer]
    How many seconds should we wait until timing out the patch run? (Defaults to 3600 seconds)
- yum_params : Optional[String]
    Any additional parameters to include in the yum upgrade command (such as including/excluding repos)
- package_list : Optional[Array[String]]
    List of packages to update or Windows updates to install (Defaults to all available updates, ignored if security_only=true)
```

#### Example:
```bash
$ puppet task run pe_patch::patch_server --params='{"reboot": "patched", "security_only": false}' --query="inventory[certname] { facts.pe_patch.patch_group = 'Week3' and facts.pe_patch.blocked = false and facts.pe_patch.package_update_count > 0}"
```

This will run a patching task against all nodes which have facts matching:

* `pe_patch.patch_group` of 'Week3'
* `pe_patch.blocked` equals `false`
* `pe_patch.package_update_count` greater than 0

The task will apply all patches (`security_only=false` & `package_list` not set) and will reboot the node after patching (`reboot=true`).

#### Example:
```bash
$ puppet task run pe_patch::patch_server --params='{"package_list": ["foo", "foo-libs"]}' --query="inventory[certname] { facts.os.family != 'windows' and facts.pe_patch.patch_group = 'VR' and facts.pe_patch.package_update_count > 0 }"
```

This will run a patching task against all nodes which have facts matching:

* `os.family` is not 'windows'
* `pe_patch.patch_group` is 'VR'
* `pe_patch.package_update_count` greater than 0

The task will apply patches for `foo` & `foo-libs` packages and will fail with an error on any nodes where either package has no update available.
If the query was altered to include Windows nodes this task would fail with an error because package_list contains non-numerical values. To install a Windows update reference the KB article ID, for example: {"package_list": ["1234567"]}

## Reference

### Facts

Most of the reporting is driven by the custom fact `pe_patch_data`, for example:

```yaml
# facter -p pe_patch
{
  package_update_count => 0,
  package_updates => [],
  security_package_updates => [],
  security_package_update_count => 0,
  blocked => false,
  blocked_reasons => [],
  blackouts => {},
  patch_group => 'Week3',
  pinned_packages => [],
  last_run => {
    date => "2018-08-07T21:55:20+10:00",
    message => "Patching complete",
    return_code => "Success",
    post_reboot => "false",
    security_only => "false",
    job_id => "60"
  }
  reboots => {
    reboot_required => false,
    apps_needing_restart => { },
    app_restart_required => false
  }
}
```

This shows there are no updates which can be applied to this server and the server doesn't need a reboot or any application restarts.  When there are updates to add, you will see similar to this:

```yaml
# facter -p pe_patch
{
  package_update_count => 6,
  package_updates => [
    "kernel.x86_64",
    "kernel-tools.x86_64",
    "kernel-tools-libs.x86_64",
    "postfix.x86_64",
    "procps-ng.x86_64",
    "python-perf.x86_64"
  ]
  security_package_updates => [],
  security_package_update_count => 0,
  blocked => false,
  blocked_reasons => [],
  blackouts => {
    Test change freeze 2 => {
      start => "2018-08-01T09:17:10+1000",
      end => "2018-08-01T11:15:50+1000"
    }
  },
  pinned_packages => [],
  patch_group => 'Week3',
  last_run => {
    date => "2018-08-07T21:55:20+10:00",
    message => "Patching complete",
    return_code => "Success",
    post_reboot => "false",
    security_only => "false",
    job_id => "60"
  }
  reboots => {
    reboot_required => true,
    apps_needing_restart => {
      630 => "/usr/sbin/NetworkManager --no-daemon ",
      1451 => "/usr/bin/python2 -s /usr/bin/fail2ban-server -s /var/run/fail2ban/fail2ban.sock -p /var/run/fail2ban/fail2ban.pid -x -b ",
      1232 => "/usr/bin/python -Es /usr/sbin/tuned -l -P "
    },
    app_restart_required => true
  }
}
```

Where it shows 6 packages with available updates, along with an array of the package names.  None of the packages are tagged as security related (requires Debian, a subscription to RHEL or a Windows system).  There are no blockers to patching and the blackout window defined is not in effect.

The reboot_required flag is set to true, which means there have been changes to packages that require a reboot (libc, kernel etc) but a reboot hasn't happened.  The apps_needing_restart shows the PID and command line of applications that are using files that have been upgraded but the process hasn't been restarted.

The pinned packages entry lists any packages which have been specifically excluded from being patched, from [version lock](https://access.redhat.com/solutions/98873) on Red Hat or by [pinning](https://wiki.debian.org/AptPreferences) in Debian.

Last run shows a summary of the information from the last `pe_patch::patch_server` task.

The fact `pe_patch.patch_group` can be used to assign nodes to an arbitrary group.  The fact can be used as part of the query fed into the task to determine which nodes to patch:

```bash
$ puppet task run pe_patch::patch_server --query="inventory[certname] {facts.pe_patch.patch_group = 'Week3'}"
```

### Running custom commands before patching

You can use the parameter `pe_patch::pre_patching_command` to supply a file name to be run prior to running the patch job.  The file much be executable and should exit with a return code of `0` if the command was successful.

The entry must be a single command, with no arguments or parameters.

### To reboot or not to reboot, that is the question...

The logic for how to handle reboots is a little complex as it has to handle a wide range of scenarios and desired outcomes.

There are two options which can be set that control how the reboot decision is made:

#### The `reboot` parameter

The reboot parameter is set in the `pe_patch::patch_server` task.  It takes the following options:

* "always"
  * No matter what, **always** reboot the node during the task run, even if no patches are required
* "never" (or the legacy value `false`)
  * No matter what, **never** reboot the node during the task run, even if patches have been applied
* "patched" (or the legacy value `true`)
  * Reboot the node if patches have been applied
* "smart"
  * Use the OS supplied tools (e.g. `needs_restarting` on RHEL, or a pending reboot check on Windows) to determine if a reboot is required, if it is reboot, otherwise do not.

The default value is "never".

These parameters set the default action for all nodes during the run of the task.  It is possible to override the behaviour on a node by using...

#### The `reboot_override` fact

The reboot override fact is part of the `pe_patch` fact set.  It is set through the pe_patch manifest and has a default of "default".

If it is set to "default" it will take whatever reboot actions are listed in the `pe_patch::patch_server` task.  The other options it takes are the same as those for the reboot parameter (always, never, patched, smart).

During the task run, any value other than "default" will override the value for the `reboot` parameter.  For example, if the `reboot` parameter is set to "never" but the `reboot_override` fact is set to "always", the node will always reboot.  If the `reboot` parameter is set to "never" but the `reboot_override` fact is set to "default", the node will use the `reboot` parameter and not reboot.

#### Why?

By having a reboot mode set by the task parameter, it is possible to set the behaviour for all nodes in a patching run (I do 100's at once).  Having the override functionality provided by the fact, you can allow individual nodes included in the patching run excluded from the reboot behaviour.  Maybe there are a couple of nodes you know you need to patch but you can't reboot them immediately, you can set their reboot_override fact to "never" and handle the reboot manually at another time.

### Task output

If there is nothing to be done, the task will report:

```json
{
  "pinned_packages" : [ ],
  "security" : false,
  "return" : "Success",
  "start_time" : "2018-08-08T07:52:28+10:00",
  "debug" : "",
  "end_time" : "2018-08-08T07:52:46+10:00",
  "reboot" : "never",
  "packages_updated" : "",
  "job_id" : "",
  "message" : "No patches to apply"
}
```

If patching was executed, the task will report similar to below:

```json
{
  "pinned_packages" : [ ],
  "security" : false,
  "return" : "Success",
  "start_time" : "2018-08-07T21:55:20+10:00",
  "debug" : "TRIMMED DUE TO LENGTH FOR THIS EXAMPLE, WOULD NORMALLY CONTAIN FULL COMMAND OUTPUT",
  "end_time" : "2018-08-07T21:57:11+10:00",
  "reboot" : "never",
  "packages_updated" : [ "NetworkManager-1:1.10.2-14.el7_5.x86_64", "NetworkManager-libnm-1:1.10.2-14.el7_5.x86_64", "NetworkManager-team-1:1.10.2-14.el7_5.x86_64", "NetworkManager-tui-1:1.10.2-14.el7_5.x86_64", "binutils-2.27-27.base.el7.x86_64", "centos-release-7-5.1804.el7.centos.2.x86_64", "git-1.8.3.1-13.el7.x86_64", "gnupg2-2.0.22-4.el7.x86_64", "kernel-tools-3.10.0-862.3.3.el7.x86_64", "kernel-tools-libs-3.10.0-862.3.3.el7.x86_64", "perl-Git-1.8.3.1-13.el7.noarch", "python-2.7.5-68.el7.x86_64", "python-libs-2.7.5-68.el7.x86_64", "python-perf-3.10.0-862.3.3.el7.centos.plus.x86_64", "selinux-policy-3.13.1-192.el7_5.3.noarch", "selinux-policy-targeted-3.13.1-192.el7_5.3.noarch", "sudo-1.8.19p2-13.el7.x86_64", "yum-plugin-fastestmirror-1.1.31-45.el7.noarch", "yum-utils-1.1.31-45.el7.noarch" ],
  "job_id" : "60",
  "message" : "Patching complete"
}
```

If patching was blocked, the task will report similar to below:

```json
Error: Task exited : 100
Patching blocked
```
A summary of the patch run is also written to `/opt/puppetlabs/pe_patch/run_history`, the last line of which is used by the `pe_patch.last_run` fact.

```bash
2018-08-07T14:47:24+10:00|No patches to apply|Success|false|false|
2018-08-07T14:56:56+10:00|Patching complete|Success|false|false|121
2018-08-07T15:04:42+10:00|yum timeout after 2 seconds : Loaded plugins: versionlock|1|||
2018-08-07T15:05:51+10:00|yum timeout after 3 seconds : Loaded plugins: versionlock|1|||
2018-08-07T15:10:16+10:00|Patching complete|Success|false|false|127
2018-08-07T21:31:47+10:00|Patching blocked |100|||
2018-08-08T07:53:59+10:00|Patching blocked |100|||
```

### pe_patch Directory and Files

Each system with the pe_patch class applied will have several files and a directory managed by the manifest.

#### Fact Generation Script

The script used to scan for updates and generate the fact data is stored in the following location based on the OS type:

* Linux - `/opt/puppetlabs/pe_patch/pe_patch_fact_generation.sh`
* Windows - `c:\ProgramData\PuppetLabs\pe_patch\pe_patch_fact_generation.ps1`

#### pe_patch directory

The pe_patch directory contains the various control files needed for this module and its tasks to work correctly.  The locations are as follows:

* Linux - `/opt/puppetlabs/pe_patch`
* Windows - `c:\ProgramData\PuppetLabs\pe_patch`

The following files are stored in this directory:

* `blackout_windows` : contains name, start and end time for all blackout windows
* `package_updates` : a list of all package updates available, populated by `pe_patch_fact_generation.sh` (Linux) or `pe_patch_fact_generation.ps1` (Windows), triggered through cron (Linux) or task scheduler (Windows)
* `security_package_updates` : a list of all security_package updates available, populated by `pe_patch_fact_generation.sh` (Linux) or `pe_patch_fact_generation.ps1` (Windows), triggered through cron (Linux) or task scheduler (Windows)
* `run_history` : a summary of each run of the `pe_patch::patch_server` task, populated by the task
* `reboot_override` : if present, overrides the `reboot=` parameter to the task
* `patch_group` : if present, sets the value for the fact `pe_patch.patch_group`
* `reboot_required` : if the OS can determine that the server needs to be rebooted due to package changes, this file contains the result.  Populates the fact reboot.reboot_required.
* `apps_to_restart` : (Linux only) a list of processes (PID and command line) that haven't been restarted since the packages they use were patched.  Sets the fact reboot.apps_needing_restart and .reboot.app_restart_required.

With the exception of the run_history file and Windows pe_patch scripts, all files in the pe_patch directory will be regenerated after a puppet run and a run of the `pe_patch_fact_generation.sh` or `pe_patch_fact_generation.ps1` script, which runs every hour by default.  If run_history is removed, the same information can be obtained from PDB, apt/yum, syslog or the Windows event log.

### Windows Systems

As Windows includes no native command line tools to manage update installation, PowerShell scripts have been written utilising the Windows Update agent APIs that handle the update search, download, and installation process:

* `pe_patch_fact_generation.ps1` which scans for updates and generates fact data (as above)
* `pe_patch_groups.ps1` is utilised by the `patch_server` task and underlying ruby script to handle the update installation process

#### Supported Windows Versions

Windows Server 2008 (x86 and x64) through to 2019 have been tested. The code should also function on the equivalent client versions of Windows (e.g. Vista and newer), however this has not been thoroughly tested.

#### Configuration of Windows Update

This module does *not* handle the configuration of the update source or any of the other Windows Update settings - it simply triggers a search (fact generation) or search, download and install (patch_server task). It is recommended to use the [puppetlabs wsus_client module](https://forge.puppet.com/puppetlabs/wsus_client) to configure the following options:

* WSUS server if you are using one (although this is not strictly required)
* Set the mode to automatically download updates and notify for install (`AutoNotify`)

For example:

```puppet
class { 'wsus_client':
  server_url             => 'http://my-wsus-server.internal:8530', # WSUS Server
  enable_status_server   => true                                   # Send status to WSUS too
  auto_update_option     => 'AutoNotify',                          # automatically download updates and notify for install
}
```

## Limitations

* RedHat 5 based systems have support but lack a lot of the yum functionality added in 6, so things like the upgraded package list and job ID will be missing.

* PowerShell version 3.0 or newer is required on Windows Systems.

* If updates or packages are installed outside of this script (e.g. by a user or another automated process), the results will not be captured in the facts.

* On Windows systems, the timeout parameter of the `patch_server` task is implemented as a maintenance window end time (e.g. start time + timeout). This is used by doing a calculation prior to installing each update. If there is insufficient available, the update run will stop. However, at this stage each update is estimated to take 5 minutes to install. This will be improved in a future release to perform an estimation based on update size or type (e.g. an SCCM-like 5 minutes for hotfix, 30 minutes for cumulative update).

## Development

Fork, develop, submit a pull request

## Contributors

- [Tony Green](mailto:tgreen@albatrossflavour.com) | [@albatrossflavor](https://twitter.com/albatrossflavor) | [http://albatrossflavour.com](http://albatrossflavour.com)
- NotPotato
- [Brett Gray](https://github.com/beergeek)
- [Rob Nelson](https://github.com/rnelson0)
- [Tommy McNeely](https://github.com/tjm)
- [Geoff Williams](https://github.com/GeoffWilliams)
- [Jake Rogers](https://github.com/JakeTRogers)
- [Nathan Giuliani](https://github.com/nathangiuliani)
- [Clive Weir](https://github.com/cliveweir)
