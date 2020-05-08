### Show all patch groups

```
puppet=query 'fact_contents[value, count()] { path = ["pe_patch", "patch_group"] group by value }'
```

### Show nodes with available updates

```
puppet-query 'inventory[certname] { facts.pe_patch.package_update_count > 0 }'
```

### Show nodes pending a reboot

```
puppet-query 'inventory[certname] { facts.pe_patch.reboots.reboot_required = true }'
```
