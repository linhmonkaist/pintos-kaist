#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdint.h>
#include "threads/thread.h"

void syscall_init (void);

struct fd_list_elem {
    int fd;
    struct list_elem elem;
    struct file *file_ptr;
};

#endif /* userprog/syscall.h */
