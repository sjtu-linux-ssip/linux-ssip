#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/moduleparam.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("https://github.com/SanqingQi/Integrity_Protection_IS415");
MODULE_DESCRIPTION("a loadable kernel module to hook `sys_openat` + `sys_write`, for linux kernel v5.4.0");

typedef void (*syscall_ptr_t)(void);
syscall_ptr_t *syscall_table = NULL;

typedef asmlinkage long (*sys_openat_t)(const struct pt_regs *regs);
sys_openat_t sys_openat_orig = NULL;

typedef asmlinkage long (*sys_write_t)(const struct pt_regs *regs);
sys_write_t sys_write_orig = NULL;

unsigned int level;
pte_t *pte;

// protected file name
static char *protected_filename;
module_param(protected_filename, charp, 0644);
// threat uid/gid (-1: all except root)
static int threat_uid = -1;
static int threat_gid = -1;
module_param(threat_uid, int, 0644);
module_param(threat_gid, int, 0644);

// open file info
static unsigned int openfile_fd = 0;
static unsigned int openfile_pid = 0;

// send SIGKILL to kill threat process
int kill_threat_process(struct task_struct *task) {
	struct kernel_siginfo info;
	memset(&info, 0, sizeof(struct kernel_siginfo));
	info.si_signo = SIGKILL;
	return send_sig_info(SIGKILL, &info, task);
}

static char *duplicate_filename(const char __user *filename) {
    char *kernel_filename;
    kernel_filename = kmalloc(4096, GFP_KERNEL);

    if (!kernel_filename) {
        return NULL;
    }

	if (strncpy_from_user(kernel_filename, filename, 4096) < 0) {
		kfree(kernel_filename);
		return NULL;
	}

    return kernel_filename;
}


// overloaded sys_openat handler
asmlinkage long sys_openat_hook(const struct pt_regs *regs) {
    char *kernel_filename = duplicate_filename((void*)regs->si);

    if (!strncmp(kernel_filename, protected_filename, strlen(protected_filename))) {
        kfree(kernel_filename);
        openfile_fd = sys_openat_orig(regs);
        openfile_pid = current->pid;
        return openfile_fd;
    }

    kfree(kernel_filename);
    return sys_openat_orig(regs);
}


// overloaded sys_write handler
asmlinkage long sys_write_hook(const struct pt_regs *regs) {

    if (current->pid == openfile_pid && regs->di == openfile_fd) {
    //if (current->pid == openfile_pid) {
        //printk("[DEBUG] regs->di: %ld, openfile_fd: %d", regs->di, openfile_fd);
        if ((current->cred->uid).val && (current->cred->gid).val) {
            if (threat_uid == -1 || threat_uid == (current->cred->uid).val) {
    			if (threat_gid == -1 || threat_gid == (current->cred->gid).val) {
    				printk("potential threat detected!");
    				printk("attacker pid: %d, uid: %d, gid: %d",
                        current->pid, (current->cred->uid).val, (current->cred->gid).val);
    				printk("protect victim file %s from written", protected_filename);
                    if (kill_threat_process(current) < 0) {
						printk("error sending signal");
					} else {
						printk("killed responsible process");
						return 0;
					}
    			}
    		}
        }
    }

    return sys_write_orig(regs);
}


// module init function
static int __init mod_sys_openat_write_hook_init(void) {
	syscall_table = (syscall_ptr_t*)kallsyms_lookup_name("sys_call_table");

	// save the original syscall handler
    sys_openat_orig = (sys_openat_t)syscall_table[__NR_openat];
	sys_write_orig = (sys_write_t)syscall_table[__NR_write];

	// unprotect syscall_table memory page
	pte = lookup_address((unsigned long)syscall_table, &level);

	// change PTE to allow writing
	set_pte_atomic(pte, pte_mkwrite(*pte));

	// overwrite the __NR_* entry with address to our hook
    syscall_table[__NR_openat] = (syscall_ptr_t)sys_openat_hook;
	syscall_table[__NR_write] = (syscall_ptr_t)sys_write_hook;

	// reprotect page
	set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));

	printk("Installed mod_sys_openat_write_hook module");
	return 0;
}


// module cleanup function
static void __exit mod_sys_openat_write_hook_exit(void) {
	// change PTE to allow writing
	set_pte_atomic(pte, pte_mkwrite(*pte));

	// restore syscall_table to the original state
    syscall_table[__NR_openat] = (syscall_ptr_t)sys_openat_orig;
	syscall_table[__NR_write] = (syscall_ptr_t)sys_write_orig;

	// reprotect page
	set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));

	printk("Uninstalled mod_sys_openat_write_hook module");
}


module_init(mod_sys_openat_write_hook_init);
module_exit(mod_sys_openat_write_hook_exit);
