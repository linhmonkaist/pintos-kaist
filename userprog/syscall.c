#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

//solution
struct lock filesys_lock; 
//Done

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* Fuction to make file descroption*/
static int get_new_fd(struct thread *t){
	struct list *cur_fd_list = &t -> fd_list; 
	struct filde *fld; 
	int32_t new_fd = 2; 
	int32_t cur_fd; 
	struct list_elem *e = list_begin(cur_fd_list);
	while (e != list_end (cur_fd_list)){
		cur_fd = list_entry (e, struct filde, elem) -> fd;
		if ((cur_fd == 0) || (cur_fd == 1)){
			e = list_next(e);
			continue;
		}
		if (cur_fd != new_fd){
			break;
		}
		e = list_next(e);
		new_fd ++; 
	}
	return new_fd; 
}

/*Fuction to check string is valid or not*/
static bool check_string(const char *filename){
	if (filename == NULL || strlen(filename) == 0 || !is_user_vaddr(filename))
		return false;
	return true; 
}

/* fuction to handle open syscall*/
static uint64_t syscall_open(struct intr_frame *f) {
	const char *file_name = (const char *) f -> R.rdi;
	struct file *file;
	int fd; 
	if (!check_string(file_name)){
		thread_current() -> exit_status = -1;
		thread_exit(); 
	}
 
	lock_accquire(&filesys_lock);
	file = filesys_open(file_name); 

	if (file == NULL) {lock_release(&filesys_lock); return -1;}

	fd = get_new_fd(thread_current());
	lock_release(&filesys_lock); 

	return fd;
}

/*function to handle read from STDIN*/
static void handle_STDIN(struct intr_frame *f){
	char *buf = (char *) f->R.rsi;
	for (size_t reading = 0; reading < f->R.rdx; reading++)
		buf[f->R.rdx] = input_getc ();
}
/*Function to handle read system call*/
static uint64_t syscall_read(struct intr_frame *f){
	struct thread *t = thread_current(); 
	int32_t fd = f -> R.rdi; 
	struct filde *fld = NULL;
	int ans = -1; 
	lock_acquire (&filesys_lock);
	for (struct list_elem *e = list_begin(&t->fd_list);
		e != list_end(&t->fd_list);
		e = list_next (e)){
			if (list_entry (e, struct filde, elem) -> fd == fd){
				fld = list_entry (e, struct filde, elem); 
				break; 
			}
		}
	if (fld){
		switch (fld -> type){
		case STDOUT:
			break;
		case STDIN:
			handle_STDIN(f);
		default:
			//solution
			ans = file_read (fld -> obj -> file, (char *) f->R.rsi, f->R.rdx); 
			break;
		}
	}
	lock_release (&filesys_lock);
	return ans;
}
/*Function to handle write system call*/
static uint64_t syscall_write(struct intr_frame *f){
	struct thread *t = thread_current(); 
	int32_t fd = f -> R.rdi; 
	struct filde *fld = NULL;
	int ans = -1; 
	lock_acquire (&filesys_lock);
	for (struct list_elem *e = list_begin(&t->fd_list);
		e != list_end(&t->fd_list);
		e = list_next (e)){
			if (list_entry (e, struct filde, elem) -> fd == fd){
				fld = list_entry (e, struct filde, elem); 
				break; 
			}
		}
	//solution
	if (fld){
		switch (fld -> type){
			case STDIN:
				lock_release (&filesys_lock);
				return -1; 
				break;
			case STDOUT:
				putbuf (f->R.rsi, f->R.rdx);
				ans = f -> R.rdx;
				break;
			default:
				ans = file_write(fld->obj->file, f->R.rsi, f->R.rdx);
				break;
		}
	}
	lock_release (&filesys_lock);
	return ans; 
}
/*Funtion to handle close system call*/
static uint64_t syscall_close(struct intr_frame *f){
	struct thread *t = thread_current(); 
	int32_t fd = f -> R.rdi; 
	struct filde *fld = NULL;
	lock_acquire(&filesys_lock);
	for (struct list_elem *e = list_begin(&t->fd_list);
		e != list_end(&t->fd_list);
		e = list_next (e)){
			if (list_entry (e, struct filde, elem) -> fd == fd){
				fld = list_entry (e, struct filde, elem); 
				break; 
			}
		}
	int ans = -1; 
	if (fld){
		list_remove (&fld->elem);
		if (fld -> type == FILE){
			fld -> obj -> ref_cnt --; 
			if (fld -> obj -> ref_cnt == 0){
				file_close(fld -> obj -> file);
				free(fld -> obj);
			}
		}
		free(fld);
		ans = 1; 
	}
	lock_release (&filesys_lock);
	return ans; 
}
/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	switch (f -> R.rax)
	{
	case SYS_OPEN:
		check_valid_va (f->R.rdi);
      	f->R.rax = open (f->R.rdi);
		break;
	case SYS_FILESIZE:
		struct thread *t = thread_current(); 
		int32_t fd = f -> R.rdi; 
		struct filde *fld = NULL;
		lock_acquire(&filesys_lock);
		for (struct list_elem *e = list_begin(&t->fd_list);
			e != list_end(&t->fd_list);
			e = list_next (e)){
				if (list_entry (e, struct filde, elem) -> fd == fd){
					fld = list_entry (e, struct filde, elem); 
					break; 
				}
			}
		if (fld){
			f ->R.rax = inode_length (fld -> obj -> file ->inode);
			break; 
		}
		f ->R.rax = -1; 
		break; 
	case SYS_READ:
		check_valid_va();
		f -> R.rax = syscall_read(f);
		break; 
	case SYS_WRITE:
		check_valid_va();
		f -> R.rax = syscall_write(f);
		break; 
	case SYS_SEEK:
		check_valid_va(); 
		//solution
		struct thread *t = thread_current(); 
		int32_t fd = f -> R.rdi; 
		struct filde *fld = NULL;
		lock_acquire(&filesys_lock);
		for (struct list_elem *e = list_begin(&t->fd_list);
			e != list_end(&t->fd_list);
			e = list_next (e)){
				if (list_entry (e, struct filde, elem) -> fd == fd){
					fld = list_entry (e, struct filde, elem); 
					break; 
				}
			}
		if (fld && fld->obj)
			file_seek (fld->obj->file, f->R.rsi);
		lock_release (&filesys_lock);
		f -> R.rax = 0; 
	case SYS_TELL:
		struct thread *t = thread_current(); 
		int32_t fd = f -> R.rdi; 
		struct filde *fld = NULL;
		lock_acquire(&filesys_lock);
		for (struct list_elem *e = list_begin(&t->fd_list);
			e != list_end(&t->fd_list);
			e = list_next (e)){
				if (list_entry (e, struct filde, elem) -> fd == fd){
					fld = list_entry (e, struct filde, elem); 
					break; 
				}
			}
		if (fld && fld->obj)
			f -> R.rax = file_tell (fld->obj->file);
			lock_release (&filesys_lock);
			break;
		lock_release (&filesys_lock);
		f -> R.rax = -1;
		break; 
	case SYS_CLOSE:
		f -> R.rax = syscall_close(f);
		break;  
	}
}
