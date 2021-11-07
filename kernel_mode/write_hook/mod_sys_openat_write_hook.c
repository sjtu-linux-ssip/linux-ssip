#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <linux/types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("https://github.com/sjtu-linux-ssip/linux-ssip");
MODULE_DESCRIPTION("a loadable kernel module to hook `sys_openat` + `sys_write`, for linux kernel v5.4.0");

// netlink related
#define MSG_LEN 256
#define WRITE_NETLINK_PORT 9096
#define ALLOW_MSG '1'
#define DENY_MSG '0'
#define WRITE_PARSE_FORMAT "%d@%d@%s"

typedef struct {
    char* msg;
    uint16_t len;
	int res;
} session_t;

session_t session;

struct sock *nlsk = NULL;
extern struct net init_net;

// syscall table related
typedef void (*syscall_ptr_t)(void);
syscall_ptr_t *syscall_table = NULL;

typedef asmlinkage long (*sys_openat_t)(const struct pt_regs *regs);
sys_openat_t sys_openat_orig = NULL;

typedef asmlinkage long (*sys_write_t)(const struct pt_regs *regs);
sys_write_t sys_write_orig = NULL;

unsigned int level;
pte_t *pte;

// open file info
static unsigned int openfile_fd = 0;
static unsigned int openfile_pid = 0;
static char openfile_name[MSG_LEN];


// send netlink message
int send_nl_msg(char *pbuf, uint16_t len) {
    struct sk_buff *nl_skb;
    struct nlmsghdr *nlh;

    int ret;

    /* create sk_buff memory */
    nl_skb = nlmsg_new(len, GFP_ATOMIC);
    if (!nl_skb) {
        printk("netlink alloc failure\n");
        return -1;
    }

    /* set netlink message header */
    nlh = nlmsg_put(nl_skb, 0, 0, NETLINK_USERSOCK, len, 0);
    if (nlh == NULL) {
        printk("nlmsg_put failaure \n");
        nlmsg_free(nl_skb);
        return -1;
    }

    /* copy data and send */
    memcpy(nlmsg_data(nlh), pbuf, len);
    ret = netlink_unicast(nlsk, nl_skb, WRITE_NETLINK_PORT, MSG_DONTWAIT);

    return ret;
}


// receive netlink message
static void recv_nl_msg(struct sk_buff *skb) {
    struct nlmsghdr *nlh = NULL;
    char *umsg = NULL;

    if (skb->len >= nlmsg_total_size(0)) {
        nlh = nlmsg_hdr(skb);
        umsg = NLMSG_DATA(nlh);
        printk("(write) message from user: %s\n", umsg);
        if (umsg[0] == ALLOW_MSG) {
            session.res = 1;  // allow the operation
        } else if (umsg[0] == DENY_MSG){
            session.res = 0;  // deny the operation
        } else {
            session.res = -1;  // received no response
        }
    }
}

// set callback function
struct netlink_kernel_cfg cfg = {
        .input  = recv_nl_msg,
};


// send SIGKILL to kill threat process
int kill_threat_process(struct task_struct *task) {
	struct kernel_siginfo info;
	memset(&info, 0, sizeof(struct kernel_siginfo));
	info.si_signo = SIGKILL;
	return send_sig_info(SIGKILL, &info, task);
}

int flexible_check_valid_path(char *path) {
    if (!strncmp(path, "/home/", 6)) {
        int i;
        for (i = 6; i < strlen(path); i++) {
            if (path[i] == '/') {
                break;
            }
        }
        if (i == strlen(path)) {
            return 1;
        }
        if (!strncmp(path + i, "/.", 2)) {
            return 0;
        }
        if (!strncmp(path + i, "/_", 2)) {
            return 0;
        }
        // ... more flexible cases
        return 1;
    }
    return 0;
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

    if ((current->cred->uid).val && (current->cred->gid).val) {
        char *kernel_filename = duplicate_filename((void*)regs->si);
        long ret = sys_openat_orig(regs);

        if (flexible_check_valid_path(kernel_filename)) {
            strcpy(openfile_name, kernel_filename);
            openfile_fd = ret;
            openfile_pid = current->pid;
        }

        kfree(kernel_filename);
        return ret;
    }

    return sys_openat_orig(regs);
}


// overloaded sys_write handler
asmlinkage long sys_write_hook(const struct pt_regs *regs) {

	// NOT root user/group, root is always allowed
	if ((current->cred->uid).val && (current->cred->gid).val && strlen(openfile_name) > 0) {
		if (current->pid == openfile_pid && regs->di == openfile_fd) {
			char msg[MSG_LEN];
			sprintf(msg, WRITE_PARSE_FORMAT, (current->cred->uid).val, (current->cred->gid).val, openfile_name);
			// fill in message that will be sent
			session.msg = msg;
			session.len = strlen(msg);
			session.res = -1;  // received no response
			send_nl_msg(session.msg, session.len);
			// block until getting response
			// nlsk has bound the callback `recv_nl_msg`, and if message comes, it will call `recv_nl_msg`
			while (session.res == -1) { printk(" "); }
			// got response
			if (session.res == 0) {
				// deny
				printk("potential threat detected!");
				printk("attacker pid: %d, uid: %d, gid: %d",
					current->pid, (current->cred->uid).val, (current->cred->gid).val);
				printk("protect victim file %s from written", openfile_name);
				if (kill_threat_process(current) < 0) {
					printk("error sending signal");
				} else {
					printk("killed responsible process");
					return 0;
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

	// create netlink socket
	nlsk = (struct sock *)netlink_kernel_create(&init_net, NETLINK_USERSOCK, &cfg);

	if (nlsk == NULL) {
		printk("netlink create error!\n");
		return -1;
	}

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

	// release netlink socket
	if (nlsk) {
		netlink_kernel_release(nlsk);
		nlsk = NULL;
	}

	printk("Uninstalled mod_sys_openat_write_hook module");
}


module_init(mod_sys_openat_write_hook_init);
module_exit(mod_sys_openat_write_hook_exit);
