# Getting the reboot required status

You can use the puppet facts to query the reboot required status on your nodes.


```bash
puppet-task run facter_task fact=pe_patch -q 'nodes[certname] { }' --format json  | jq '.items[] | {node: .name, reboot_required: .results.pe_patch.reboots.reboot_required, app_restart_required: .results.pe_patch.reboots.app_restart_required}'
```

The output will look like this:
```json
{
  "node": "centos.example.com",
  "reboot_required": false,
  "app_restart_required": false
}
{
  "node": "puppetmaster.example.com",
  "reboot_required": true,
  "app_restart_required": true
}
```
