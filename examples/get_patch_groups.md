# Get patch groups

To see all assigned patch groups:

```bash
puppet-task run facter_task fact=pe_patch -q 'nodes[certname] { }' --format json  | jq '.items[] | {node: .name, patch_group: .results.pe_patch.patch_group, blocked: .results.pe_patch.blocked}'
```

```json
{
  "node": "centos.example.com",
  "patch_group": null,
  "blocked": false
}
{
  "node": "puppetmaster.example.com",
  "patch_group": "42",
  "blocked": true
}
```

To see all nodes from a specific patch group ('42' in this example):
```bash
puppet-task run facter_task fact=pe_patch -q 'inventory[certname] { facts.pe_patch.patch_group = "42" }' --format json  | jq '.items[] | {node: .name, patch_group: .results.pe_patch.patch_group, blocked: .results.pe_patch.blocked}'
```

```json
{
  "node": "puppetmaster.example.com",
  "patch_group": "42",
  "blocked": true
}


To see all nodes without an assigned patch group:
```bash
puppet-task run facter_task fact=pe_patch -q 'inventory[certname] { facts.pe_patch.patch_group is null }' --format json  | jq '.items[] | {node: .name, patch_group: .results.pe_patch.patch_group, blocked: .results.pe_patch.blocked}'
```

```json
{
  "node": "centos.example.com",
  "patch_group": null,
  "blocked": false
}
```
