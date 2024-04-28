#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
//solution_2
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/init.h"
#include "threads/mmu.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "lib/string.h"
//end solution_2
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

//project 3
#include "vm/file.h"
#include "vm/vm.h"

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
	lock_init (&filesys_lock);
}


static bool
pointer_validate (const void *p) {
	if (p == NULL || !is_user_vaddr (p)){
		return false;
	}
	if (pml4_get_page(thread_current()->pml4, p) == NULL){
		return false;
	}
	return true;
}

static bool fd_arrange (const struct list_elem *A, const struct list_elem *B, void *_a UNUSED) {
	bool ans = list_entry (A, struct filde, elem) -> fd < list_entry (B, struct filde, elem) ->fd;
	return ans;
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

static struct filde *
get_filde (int32_t fd) {
	struct list *fd_list = &thread_current()->fd_list;
	struct filde *filde;
	int cnt = 0; 
	struct list_elem *e = list_begin (fd_list); 
	while (e != list_end (fd_list)) {
		filde = list_entry (e, struct filde, elem);
		cnt ++; 
		if (filde->fd != fd){
			e = list_next (e);
			continue;
		}
		return filde;
		e = list_next (e);
	}
	cnt = 0;
	return NULL;
}
/*Fuction to check string is valid or not*/
static bool check_string(const char *filename){
	if (filename == NULL || strlen(filename) == 0 || !is_user_vaddr(filename))
		return false;
	return true; 
}
static uint64_t
syscall_fork (struct intr_frame *f) {
	const char *name = (const char *) f->R.rdi;

	// lock_acquire(&filesys_lock);
	tid_t tid = process_fork (name, f);
	// lock_release(&filesys_lock);

	return tid;
}

static uint64_t syscall_exec (struct intr_frame *f) {
	char *unused;
	char *fn_copy = palloc_get_page (0);
	if (fn_copy == NULL) thread_exit ();

	const char *fname = (const char *) f->R.rdi;
	// if (strlen(fname) < PGSIZE){
	// 	strlcpy (fn_copy, fname, strlen(fname) + 1);
	// } else {
		strlcpy (fn_copy, fname, PGSIZE);
	// }
	
	if (strlen(fname) < PGSIZE) {
		fn_copy[strlen(fname) + 1] = 0;
	}
	fn_copy = strtok_r(fn_copy, " ", &unused);

	if (process_exec (fn_copy) == -1) {
		thread_exit ();
	}
	NOT_REACHED();
	return -1;
}
static uint64_t
syscall_create (struct intr_frame *f) {
	lock_acquire (&filesys_lock);
	int ret = filesys_create (f->R.rdi, f->R.rsi);
	lock_release (&filesys_lock);
	return ret;
}
static uint64_t
syscall_remove (struct intr_frame *f) {
	const char *fname = (const char *) f->R.rdi;
	lock_acquire (&filesys_lock);
	int ret = filesys_remove (fname);
	lock_release (&filesys_lock);
	return ret;
}
static void get_file_with_fd(struct filde *filde, int fd, struct file_obj *obj, struct thread *t, struct file *file){
	*obj = (struct file_obj) {
		.file = file,
		.ref_cnt = 1,
	};
	*filde = (struct filde) {
		.fd = fd,
		.obj = obj,
		// .type = FILE,
	};
	list_insert_ordered (&t->fd_list, &filde->elem, fd_arrange, NULL);
}
static uint64_t
syscall_open (struct intr_frame *f) {
	const char *fname = (const char *) f->R.rdi;
	struct thread *t = thread_current ();
	struct file *file;
	struct filde *filde;
	int fd;
	int ret = -1;

	lock_acquire(&filesys_lock);
	fd = get_new_fd (t);

	if (fd < 0){
		lock_release (&filesys_lock);
		return -1;
	}

	file = filesys_open(fname);
	if (file == NULL){
		lock_release (&filesys_lock);
		return -1;
	}
	filde = (struct filde *) malloc (sizeof (struct filde));
	if (filde == NULL){
		file_close (file);
		lock_release (&filesys_lock);
		return -1;
	}

	struct file_obj *obj = (struct file_obj *) malloc (sizeof (struct file_obj));
	if (obj == NULL){
		free (filde);
		lock_release (&filesys_lock);
		return -1;
	}

	get_file_with_fd(filde, fd, obj, t, file); 
		
	lock_release (&filesys_lock);
	return fd;
}

static uint64_t
syscall_filesize (struct intr_frame *f) {
	struct thread *t = thread_current(); 
	int32_t fd = f -> R.rdi; 
	struct filde *fld = NULL;
	int ans = -1;
	lock_acquire(&filesys_lock);
	for (struct list_elem *e = list_begin(&t->fd_list);
		e != list_end(&t-> fd_list);
		e = list_next (e)){
			if (list_entry (e, struct filde, elem) -> fd == fd){
				fld = list_entry (e, struct filde, elem); 
				break; 
			}
		}
	if (!fld){
		lock_release (&filesys_lock);
		return -1; 
	}
	ans = file_length (fld -> obj -> file);
	lock_release (&filesys_lock);
	return ans;
}

/*function to handle read from STDIN*/
static size_t handle_STDIN(struct intr_frame *f){
	char *buf = (char *) f->R.rsi;
	size_t byte_get = 0;
	for (size_t reading = 0; reading < f->R.rdx; reading++){
		buf[f->R.rdx] = input_getc ();
		byte_get++; 
	}
	return byte_get; 
}
/*Function to handle read system call*/
static uint64_t
syscall_read (const struct intr_frame *f) {
	struct thread *t = thread_current(); 
	int32_t fd = f -> R.rdi; 
	struct filde *fld =get_filde (fd);

	if (!fld) return -1; 
	// if (fld -> type == STDOUT) return -1; 
	// if (fld -> type == STDIN){
	if (fld -> fd == 1) return -1; 
	if (fld -> fd == 0){
		return handle_STDIN(f); 
	}

	lock_acquire (&filesys_lock);
	int32_t ans = file_read (fld -> obj -> file, f->R.rsi, f->R.rdx); 
	lock_release (&filesys_lock);
	return ans;
}
/*Function to handle write system call*/
static uint64_t
syscall_write (struct intr_frame *f) {
	struct filde *filde = get_filde(f->R.rdi);
	if (!filde) return -1;
	// if (filde -> type == STDIN) return -1; 
	// if (filde -> type == STDOUT){
	if (filde -> fd == 0) return -1; 
	if (filde -> fd == 1){
		putbuf(f->R.rsi, f->R.rdx);
		return f->R.rdx; 
	}
	lock_acquire (&filesys_lock);
	int32_t ret = file_write (filde->obj->file, f->R.rsi, f->R.rdx);
	lock_release (&filesys_lock);
	return ret;
}
static void syscall_seek (struct intr_frame *f) {
	struct thread *t = thread_current(); 
	int32_t fd = f -> R.rdi; 
	struct filde *fld = NULL;
	for (struct list_elem *e = list_begin(&t->fd_list);
		e != list_end(&t-> fd_list); e = list_next (e)){
			if (list_entry (e, struct filde, elem) -> fd == fd){
				fld = list_entry (e, struct filde, elem); 
				break; 
			}
		}
	if (!fld || !fld -> obj) return; 
	struct file *file = fld->obj->file; 
	lock_acquire(&filesys_lock);
	file_seek (file, f->R.rsi);
	lock_release (&filesys_lock);
}
static uint64_t
syscall_tell (struct intr_frame *f) {
	struct thread *t = thread_current(); 
	int32_t fd = f -> R.rdi; 
	struct filde *fld = NULL;
	
	for (struct list_elem *e = list_begin(&t->fd_list);
		e != list_end(&t-> fd_list); e = list_next (e)){
			if (list_entry (e, struct filde, elem) -> fd == fd){
				fld = list_entry (e, struct filde, elem); 
				break; 
			}
		}
	if (!fld || !fld -> obj) return;
	struct file *file = fld->obj->file; 
	lock_acquire(&filesys_lock);
	int32_t ans = file_tell (file); 
	lock_release (&filesys_lock);
	return ans;
}

/*Funtion to handle close system call*/
static uint64_t
syscall_close (struct intr_frame *f) {
	int32_t fd = f->R.rdi;
	struct filde *filde = get_filde (fd);
	if (!filde){ 
		// lock_release (&filesys_lock);
		return -1; 
	}
	list_remove (&filde->elem);
	if (filde -> fd < 2) {
		free(filde); 
		// lock_release (&filesys_lock);
		return 1;
	}
	struct file_obj *obj = filde -> obj; 
	lock_acquire (&filesys_lock);
	if (-- obj->ref_cnt == 0) {
		file_close (obj->file);
		free (obj);
	}
	free (filde);
	lock_release (&filesys_lock);
	return 1;
}
/*function to verify address of mmap before pass to do_mmap
for project3*/
static struct file * process_get_file(int fd) {
	struct list_elem *e;
	for (e = list_begin(&thread_current()->fd_list);
		e != list_end(&thread_current()->fd_list); e=list_next(e)) {
		if (fd == list_entry(e, struct fd_list_elem, elem)->fd)
			return list_entry(e, struct fd_list_elem, elem)->file_ptr;
	}
	return NULL;
}

static uint64_t mmap(void *addr, size_t length, int writeable, int fd, off_t offset){
	if (addr == NULL) return NULL; 	//address not present
	if (addr != pg_round_down(addr) || offset != pg_round_down(offset)) return NULL; //addr or offset not page-aligned
	if (!is_user_vaddr(addr) || !is_user_vaddr(addr + length)) return NULL; //addr, addr + length not in user address
	if (spt_find_page(&thread_current() -> spt, addr)) return NULL; 
	struct file *f = process_get_file(fd); 
	if (!f) return NULL; 
	if (file_length(f) == 0 || (int) length <= 0) return NULL; 
	return do_mmap(addr, length, writeable, f, offset);
}

/* 
* Funtion to handle syscall munmap
* project3 */
void munmap(void *addr){
	do_munmap(addr); 
}
//end

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
//project3
#ifdef VM
	thread_current() -> rsp = f -> rsp; 
#endif
//end
	char *fname = (char *) f->R.rdi;
	switch (f->R.rax) {
		case SYS_HALT:
			power_off ();
			NOT_REACHED ();
			break;
		case SYS_EXIT:
			thread_current ()-> exit_status = f->R.rdi;
			thread_exit ();
			NOT_REACHED ();
			break;
		case SYS_FORK:
			if (!pointer_validate (fname)){
				thread_current () -> exit_status = -1;
				thread_exit ();
			}
			f->R.rax = syscall_fork (f);
			break;
		case SYS_EXEC:
			if (!pointer_validate (f->R.rdi)){
				thread_current() -> exit_status = -1;
				thread_exit(); 
			}
			f->R.rax = syscall_exec (f);
			break;
		case SYS_WAIT:
			f->R.rax = process_wait(f->R.rdi);
			break;
		case SYS_CREATE:
			if (!pointer_validate (fname) || !strcmp (fname, "")){
				thread_current() -> exit_status = -1;
				thread_exit();
			}
			f->R.rax = syscall_create (f);
			break;
		case SYS_REMOVE:
			if (!pointer_validate (fname)){
				thread_current() -> exit_status = -1;
				thread_exit(); 
			}
			f->R.rax = syscall_remove (f);
			break;
		case SYS_OPEN:
			if (!pointer_validate (fname)){
				thread_current ()-> exit_status = -1;
				thread_exit ();
			}
			f->R.rax = syscall_open (f);
			break;
		case SYS_FILESIZE:
			f->R.rax = syscall_filesize (f);
			break;
		case SYS_READ:
			if (!pointer_validate (f -> R.rsi)){
				thread_current() -> exit_status = -1;
				thread_exit(); 
			}
			f->R.rax = syscall_read (f);
			break;
		case SYS_WRITE:
			if (!pointer_validate (f -> R.rsi)){
				thread_current() -> exit_status = -1;
				// printf ("%s: exit(%d)\n", thread_current() ->name, thread_current() ->exit_status);
				thread_exit(); 
			}
			f->R.rax = syscall_write (f);
			break;
		case SYS_SEEK:
			syscall_seek (f);
			f->R.rax = 0;
			break;
		case SYS_TELL:
			f->R.rax = syscall_tell (f);
			break;
		case SYS_CLOSE:
			f->R.rax = syscall_close (f);
			break;
		case SYS_DUP2:
			f->R.rax = -1;
			break;
		//project3
		case SYS_MMAP:
			f->R.rax = mmap(f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
			break; 
		case SYS_MUNMAP:
			munmap(f -> R.rdi);
			break; 
		//end
		default:
			printf ("Unexpected Syscall: %llx", f->R.rax);
			f->R.rax = -1;
			break;
	}
}
