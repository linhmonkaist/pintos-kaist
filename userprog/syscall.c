#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/init.h"
#include "threads/mmu.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "devices/input.h"
#include "lib/string.h"

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
validate_ptr (const void *p, size_t size, bool writable) {
	if (p == NULL || !is_user_vaddr (p)){
		return false;
	}
	if (pml4_get_page(thread_current()->pml4, p) == NULL){
		return false;
	}
	return true;
}
static bool
validate_string (const void *p) {
	if (p == NULL || !is_user_vaddr (p)){
		return false;
	}
	if (pml4_get_page(thread_current()->pml4, p) == NULL){
		return false;
	}
	return true;
}

static bool fd_sort (const struct list_elem *A, const struct list_elem *B, void *_a UNUSED) {
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
get_filde_by_fd (int32_t fd) {
	struct list *fd_list = &thread_current()->fd_list;
	struct list_elem *e;
	struct filde *filde;
	for (e = list_begin (fd_list); e != list_end (fd_list); e = list_next (e)) {
		filde = list_entry (e, struct filde, elem);
		if (filde->fd == fd)
			return filde;
	}
	return NULL;
}
/*Fuction to check string is valid or not*/
static bool check_string(const char *filename){
	if (filename == NULL || strlen(filename) == 0 || !is_user_vaddr(filename))
		return false;
	return true; 
}
static uint64_t
SyS_fork (struct intr_frame *f) {
	const char *name = (const char *) f->R.rdi;

	if (!validate_string (name)){
		thread_current () -> exit_status = -1;
		thread_exit ();
	}

	// lock_acquire(&filesys_lock);
	tid_t tid = process_fork (name, f);
	// lock_release(&filesys_lock);

	return tid;
}

static uint64_t
SyS_exec (struct intr_frame *f) {
	char *unused;
	if (!validate_string (f->R.rdi)){
		thread_current() -> exit_status = -1;
		thread_exit(); 
	}

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

	if (process_exec (fn_copy) == -1) thread_exit ();
	NOT_REACHED();
	return -1;
}
static uint64_t
SyS_create (struct intr_frame *f) {
	const char *fname = (const char *) f->R.rdi;

	if (!validate_string (fname) || !strcmp (fname, "")){
		thread_current() -> exit_status = -1;
		thread_exit();
	}

	lock_acquire (&filesys_lock);
	int ret = filesys_create (f->R.rdi, f->R.rsi);
	lock_release (&filesys_lock);
	return ret;
}
static uint64_t
SyS_remove (struct intr_frame *f) {
	const char *fname = (const char *) f->R.rdi;

	if (!validate_string (fname)){
		thread_current() -> exit_status = -1;
		thread_exit(); 
	}

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
		.type = FILE,
	};
	list_insert_ordered (&t->fd_list, &filde->elem, fd_sort, NULL);
}
static uint64_t
SyS_open (struct intr_frame *f) {
	const char *fname = (const char *) f->R.rdi;
	struct thread *t = thread_current ();
	struct file *file;
	struct filde *filde;
	int fd;
	int ret = -1;

	if (!validate_string (fname)){
		thread_current ()-> exit_status = -1;
		thread_exit ();
	}

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
SyS_filesize (struct intr_frame *f) {
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
SyS_read (const struct intr_frame *f) {
	if (!validate_string (f -> R.rsi)){
		thread_current() -> exit_status = -1;
		thread_exit(); 
	}

	struct thread *t = thread_current(); 
	int32_t fd = f -> R.rdi; 
	struct filde *fld =get_filde_by_fd (fd);

	if (!fld) return -1; 
	if (fld -> type == STDOUT) return -1; 
	if (fld -> type == STDIN){
		return handle_STDIN(f); 
	}

	lock_acquire (&filesys_lock);
	int32_t ans = file_read (fld -> obj -> file, f->R.rsi, f->R.rdx); 
	lock_release (&filesys_lock);
	return ans;
}
/*Function to handle write system call*/
static uint64_t
SyS_write (struct intr_frame *f) {
	if (!validate_string (f -> R.rsi)){
		thread_current() -> exit_status = -1;
		// printf ("%s: exit(%d)\n", thread_current() ->name, thread_current() ->exit_status);
		thread_exit(); 
	}
	struct filde *filde = get_filde_by_fd (f->R.rdi);
	if (!filde) return -1;
	if (filde -> type == STDIN) return -1; 
	if (filde -> type == STDOUT){
		putbuf(f->R.rsi, f->R.rdx);
		return f->R.rdx; 
	}
	lock_acquire (&filesys_lock);
	int32_t ret = file_write (filde->obj->file, f->R.rsi, f->R.rdx);
	lock_release (&filesys_lock);
	return ret;
}
static void SyS_seek (struct intr_frame *f) {
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
SyS_tell (struct intr_frame *f) {
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
static void
deref_file_obj (struct file_obj *obj) {
	ASSERT (obj != NULL);
	ASSERT (obj->ref_cnt > 0);

	if (--obj->ref_cnt == 0) {
		file_close (obj->file);
		free (obj);
	}
}

bool
clean_filde (struct filde *filde) {
	if (filde) {
		if (filde->type == FILE)
			deref_file_obj (filde->obj);
		free (filde);
		return true;
	}
	return false;
}

static uint64_t
__do_close (int fd) {
	int ret = -1;

	lock_acquire (&filesys_lock);
	struct filde *filde = get_filde_by_fd (fd);
	if (filde) {
		list_remove (&filde->elem);
		ret = clean_filde (filde);
	}
	lock_release (&filesys_lock);
	return ret;
}

/*Funtion to handle close system call*/
static uint64_t
SyS_close (struct intr_frame *f) {
	int32_t fd = f->R.rdi;
	struct filde *filde = get_filde_by_fd (fd);
	if (!filde){ 
		// lock_release (&filesys_lock);
		return -1; 
	}
	list_remove (&filde->elem);
	if (filde -> type != FILE) {
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
static uint64_t
SyS_dup2 (struct intr_frame *f) {
	int32_t oldfd = f->R.rdi;
	int32_t newfd = f->R.rsi;
	struct filde *filde, *new_filde;

	/* Fail if invalid fd */
	if (newfd < 0) return -1;
	filde = get_filde_by_fd (oldfd);
	new_filde = get_filde_by_fd (newfd); 

	if (!filde) return -1;
	if (newfd == oldfd) return oldfd;
	/* close if new_filde is avail. */
	if (new_filde){
		list_remove (&new_filde->elem);
		if (new_filde->type == FILE){
			struct file_obj *obj = new_filde -> obj; 
			if (--obj->ref_cnt == 0) {
				file_close (obj->file);
				free (obj);
			}
		}
		free (new_filde);
	}
	new_filde = (struct filde *)malloc(sizeof(struct filde));
	if (!new_filde){
		return -1;
	}
	lock_acquire(&filesys_lock);
	*new_filde = *filde;
	new_filde->fd = newfd;
	if (new_filde->obj)
		new_filde->obj->ref_cnt++;
	list_insert_ordered(&thread_current()->fd_list, &new_filde->elem, fd_sort, NULL);
	int ret = newfd;
	lock_release (&filesys_lock);
	return ret;
}
/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	switch (f->R.rax) {
		case SYS_HALT:
			power_off ();
			NOT_REACHED ();
			break;
		case SYS_EXIT:
			thread_current ()->exit_status = f->R.rdi;
			thread_exit ();
			NOT_REACHED ();
			break;
		case SYS_FORK:
			f->R.rax = SyS_fork (f);
			break;
		case SYS_EXEC:
			f->R.rax = SyS_exec (f);
			break;
		case SYS_WAIT:
			f->R.rax = process_wait(f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = SyS_create (f);
			break;
		case SYS_REMOVE:
			f->R.rax = SyS_remove (f);
			break;
		case SYS_OPEN:
			f->R.rax = SyS_open (f);
			break;
		case SYS_FILESIZE:
			f->R.rax = SyS_filesize (f);
			break;
		case SYS_READ:
			f->R.rax = SyS_read (f);
			break;
		case SYS_WRITE:
			f->R.rax = SyS_write (f);
			break;
		case SYS_SEEK:
			SyS_seek (f);
			f->R.rax = 0;
			break;
		case SYS_TELL:
			f->R.rax = SyS_tell (f);
			break;
		case SYS_CLOSE:
			f->R.rax = SyS_close (f);
			break;
		case SYS_DUP2:
			f->R.rax = SyS_dup2 (f);
			break;
		default:
			printf ("Unexpected Syscall: %llx", f->R.rax);
			f->R.rax = -1;
			break;
	}
}
