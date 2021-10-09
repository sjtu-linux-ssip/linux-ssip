#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/moduleparam.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("https://github.com/SanqingQi/Integrity_Protection_IS415");
MODULE_DESCRIPTION("a loadable kernel module to hook `kill syscall`, for linux kernel v5.4.0");

typedef void (*syscall_ptr_t)(void);
syscall_ptr_t *syscall_table = NULL;

typedef asmlinkage long (*sys_kill_t)(const struct pt_regs *regs);
sys_kill_t sys_kill_orig = NULL;

unsigned int level;
pte_t *pte;

// protected pid
static int protected_pid;
module_param(protected_pid, int, 0644);
// threat uid/gid (-1 if all)
static int threat_uid;
static int threat_gid;
module_param(threat_uid, int, 0644);
module_param(threat_gid, int, 0644);

// overloaded syscall handler
asmlinkage long sys_kill_hook(const struct pt_regs *regs) {

	pid_t pid = regs->di;
	int sig = regs->si;

	if (pid == protected_pid && sig == SIGKILL) {
		if (threat_uid == -1 || threat_uid == current->cred->uid) {
			if (threat_gid == -1 || threat_gid == current->cred->gid) {
				printk("potential threat detected!");
				printk("attacker pid: %d, uid: %d, gid: %d", current->pid, current->cred->uid, current->cred->gid);
				printk("protect victim process %d from killed", protected_pid);
				return 0;
			}
		}
	}

	return sys_kill_orig(regs);
}


// module init function
static int __init mod_sys_kill_hook_init(void) {
	syscall_table = (syscall_ptr_t*)kallsyms_lookup_name("sys_call_table");

	// save the original syscall handler
	sys_kill_orig = (sys_kill_t)syscall_table[__NR_kill];

	// unprotect syscall_table memory page
	pte = lookup_address((unsigned long)syscall_table, &level);

	// change PTE to allow writing
	set_pte_atomic(pte, pte_mkwrite(*pte));

	// overwrite the __NR_* entry with address to our hook
	syscall_table[__NR_kill] = (syscall_ptr_t)sys_kill_hook;

	// reprotect page
	set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));

	printk("Installed mod_sys_kill_hook module");
	return 0;
}


// module cleanup function
static void __exit mod_sys_kill_hook_exit(void) {
	// change PTE to allow writing
	set_pte_atomic(pte, pte_mkwrite(*pte));

	// restore syscall_table to the original state
	syscall_table[__NR_kill] = (syscall_ptr_t)sys_kill_orig;

	// reprotect page
	set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));

	printk("Uninstalled mod_sys_kill_hook module");
}


module_init(mod_sys_kill_hook_init);
module_exit(mod_sys_kill_hook_exit);
