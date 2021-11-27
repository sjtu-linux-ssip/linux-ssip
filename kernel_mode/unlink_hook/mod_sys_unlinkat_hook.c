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
MODULE_DESCRIPTION("a loadable kernel module to hook `sys_unlinkat`, for linux kernel v5.4.0");

// netlink related
#define MSG_LEN 256
#define UNLINK_NETLINK_PORT 9097
#define ALLOW_MSG '1'
#define DENY_MSG '0'
#define UNLINK_PARSE_FORMAT "%d#%d#%s"
#define UNLINK_NETLINK_FAMILY 30

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

typedef asmlinkage long (*sys_unlinkat_t)(const struct pt_regs *regs);
sys_unlinkat_t sys_unlinkat_orig = NULL;

unsigned int level;
pte_t *pte;


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
    nlh = nlmsg_put(nl_skb, 0, 0, UNLINK_NETLINK_FAMILY, len, 0);
    if (nlh == NULL) {
        printk("nlmsg_put failaure \n");
        nlmsg_free(nl_skb);
        return -1;
    }

    /* copy data and send */
    memcpy(nlmsg_data(nlh), pbuf, len);
    ret = netlink_unicast(nlsk, nl_skb, UNLINK_NETLINK_PORT, MSG_DONTWAIT);

    return ret;
}


// receive netlink message
static void recv_nl_msg(struct sk_buff *skb) {
    struct nlmsghdr *nlh = NULL;
    char *umsg = NULL;

    if (skb->len >= nlmsg_total_size(0)) {
        nlh = nlmsg_hdr(skb);
        umsg = NLMSG_DATA(nlh);
        printk("(unlink) message from user: %s\n", umsg);
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


// overloaded sys_unlinkat handler
asmlinkage long sys_unlinkat_hook(const struct pt_regs *regs) {

	// NOT root user/group, root is always allowed
	if ((current->cred->uid).val && (current->cred->gid).val) {
		char *kernel_filename = duplicate_filename((void*)regs->si);
		char msg[MSG_LEN];
		sprintf(msg, UNLINK_PARSE_FORMAT, (current->cred->uid).val, (current->cred->gid).val, kernel_filename);
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
			printk("protect victim file %s from deleted", kernel_filename);
			if (kill_threat_process(current) < 0) {
				printk("error sending signal");
			} else {
				printk("killed responsible process");
				return 0;
			}
		}
		kfree(kernel_filename);
	}

	return sys_unlinkat_orig(regs);
}


// module init function
static int __init mod_sys_unlinkat_hook_init(void) {
	syscall_table = (syscall_ptr_t*)kallsyms_lookup_name("sys_call_table");

	// save the original syscall handler
    sys_unlinkat_orig = (sys_unlinkat_t)syscall_table[__NR_unlinkat];

	// unprotect syscall_table memory page
	pte = lookup_address((unsigned long)syscall_table, &level);

	// change PTE to allow writing
	set_pte_atomic(pte, pte_mkwrite(*pte));

	// overwrite the __NR_* entry with address to our hook
    syscall_table[__NR_unlinkat] = (syscall_ptr_t)sys_unlinkat_hook;

	// reprotect page
	set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));

	// create netlink socket
	nlsk = (struct sock *)netlink_kernel_create(&init_net, UNLINK_NETLINK_FAMILY, &cfg);

	if (nlsk == NULL) {
		printk("netlink create error!\n");
		return -1;
	}

	printk("Installed mod_sys_unlinkat_hook module");
	return 0;
}


// module cleanup function
static void __exit mod_sys_unlinkat_hook_exit(void) {
	// change PTE to allow writing
	set_pte_atomic(pte, pte_mkwrite(*pte));

	// restore syscall_table to the original state
    syscall_table[__NR_unlinkat] = (syscall_ptr_t)sys_unlinkat_orig;

	// reprotect page
	set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));

	// release netlink socket
	if (nlsk) {
		netlink_kernel_release(nlsk);
		nlsk = NULL;
	}

	printk("Uninstalled mod_sys_unlinkat_hook module");
}


module_init(mod_sys_unlinkat_hook_init);
module_exit(mod_sys_unlinkat_hook_exit);
