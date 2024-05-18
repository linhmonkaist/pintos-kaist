#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H


#include "threads/thread.h"
#include "filesys/file.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);
bool lazy_load_segment (struct page *page, void *aux);

struct fork_fd {
    struct thread *parent;
    char *file_name;
    char *arguments;
    int arguments_count; 
};

#ifdef VM
struct lazy_load_arg{
    struct file *file; 
    off_t ofs; 
    size_t read_bytes;
    size_t zero_bytes;
	bool is_first_page;
	int num_left_page;
};
#endif

#endif /* userprog/process.h */
