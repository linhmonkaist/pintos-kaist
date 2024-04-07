#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

// struct fork_aux {
// 	struct thread *parent;
// 	struct intr_frame if_;
// 	struct semaphore dial;
// 	bool succ;
// };

struct fork_status {
    struct semaphore dial;
    bool succ;
};

struct fork_aux {
    struct thread *parent;
    struct intr_frame if_;
    struct fork_status status; // Nested structure within fork_aux
};

#endif /* userprog/process.h */
