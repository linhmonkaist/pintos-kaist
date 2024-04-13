#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H


#include "threads/thread.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

struct fork_status {
    bool succ;
    tid_t fork_id; 
    int stt_exit; 
};

struct fork_fd {
    struct thread *parent;
    char *file_name;
    struct fork_status status; // Nested structure 
    char *arguments;
    int arguments_count; 
};

#endif /* userprog/process.h */
