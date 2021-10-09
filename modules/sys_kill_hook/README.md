## Module `mod_sys_kill_hook`

* Linux Kernel version 5.4.0

* Protect certain process from killed by certain user/group

### Usage

```shell
>> make
>> insmod mod_sys_kill_hook.ko \
protected_pid=<xxx> \
threat_uid=<xxx> \  # protect from all users, specified with -1
threat_gid=<xxx>    # protect from all groups, specified with -1
# ... and then the process(protected_pid) cannot be killed by the user(threat_uid) or the group(threat_gid)
>> rmmod mod_sys_kill_hook
```

