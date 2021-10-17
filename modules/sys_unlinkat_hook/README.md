## Module `mod_sys_unlinkat_hook`

* Linux Kernel version 5.4.0
* Protect certain file from deleted by certain user/group, and kill the responsible process

### Usage

```shell
>> make
>> insmod mod_sys_unlinkat_hook.ko \
protected_filename=<xxx> \
threat_uid=<xxx> \  # protect from all users except root, NOT specify this parameter
threat_gid=<xxx>    # protect from all groups except root, NOT specify this parameter
>> rmmod mod_sys_unlinkat_hook
```

