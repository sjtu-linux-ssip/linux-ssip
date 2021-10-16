## Module `mod_sys_kill_hook`

* Linux Kernel version 5.4.0
* Protect certain process from killed by certain user/group, and kill the responsible process

### Usage

```shell
>> make
>> insmod mod_sys_kill_hook.ko \
protected_pid=<xxx> \
threat_uid=<xxx> \  # protect from all users except root, NOT specify this parameter
threat_gid=<xxx>    # protect from all groups except root, NOT specify this parameter
# ... then the process(protected_pid) cannot be killed by the user(threat_uid) or the group(threat_gid), and the attacker process is killed
>> rmmod mod_sys_kill_hook
```

