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
#ifdef VM
#include "vm/file.h"
#endif
#include "vm/vm.h"

#ifdef EFILESYS
#include "filesys/directory.h"
#include "filesys/inode.h"
#endif

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
void check_address (void *addr) {
	if (!is_user_vaddr(addr))
		SyS_exit(-1);
}
void SyS_exit (int status) {
	printf("call exit for check address");
	struct thread *t = thread_current();
	t->exit_status = status;

	printf("%s: exit(%d)\n", t->name, status); 
	thread_exit();
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
	int result = process_exec(fn_copy);

	if (result == -1) {
		thread_current() -> exit_status = -1; 
		thread_exit ();
	}
	thread_current() -> exit_status = result; 
	return result;
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
	// printf("call syscall remove: %s \n", fname); 
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
		// printf("fail cuz fd < 0 \n"); 
		return -1;
	}

	file = filesys_open(fname);
	if (file == NULL){
		lock_release (&filesys_lock);
		// printf("fail cuz file null \n");
		return -1;
	}
	filde = (struct filde *) malloc (sizeof (struct filde));
	if (filde == NULL){
		file_close (file);
		lock_release (&filesys_lock);
		// printf("fail cuz filde null \n");
		return -1;
	}

	struct file_obj *obj = (struct file_obj *) malloc (sizeof (struct file_obj));
	if (obj == NULL){
		free (filde);
		lock_release (&filesys_lock);
		// printf("fail cuz obj null \n");

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
	struct file *file = fld -> obj -> file; 

	if (!fld) return -1; 
	// if (fld -> type == STDOUT) return -1; 
	// if (fld -> type == STDIN){
	if (fld -> fd == 1) return -1; 
	if (fld -> fd == 0){
		return handle_STDIN(f); 
	}

	#ifdef VM
	if (spt_find_page(&t->spt, f->R.rsi) != NULL
			&& spt_find_page(&t->spt, f->R.rsi)->writable == 0)
		{
			t -> exit_status = -1;
			thread_exit(); 
		}
	#endif
	if (file == NULL){
		t -> exit_status = -1;
		thread_exit(); 
		return -1; 
	}
	lock_acquire (&filesys_lock);
	int32_t ans = file_read (file, f->R.rsi, f->R.rdx); 
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
	if (file_is_dir(filde->obj->file) == true)
		return -1;
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
		thread_current() -> exit_status = -1; 
		thread_exit(); 
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

static struct file * process_get_file(int fd) {
	struct list_elem *e;
	for (e = list_begin(&thread_current()->fd_list);
		e != list_end(&thread_current()->fd_list); e=list_next(e)) {
		if (fd == list_entry(e, struct filde, elem)->fd)
			return list_entry(e, struct filde, elem)-> obj -> file;
	}
	return NULL;
}
#ifdef VM
/* syscall to handle mmap */
static uint64_t syscall_mmap(void *addr, size_t length, int writeable, int fd, off_t offset){
	if (addr == NULL) return NULL; 	//address not present
	if (addr != pg_round_down(addr) || offset != pg_round_down(offset)) return NULL; //addr or offset not page-aligned
	if (!is_user_vaddr(addr) || !is_user_vaddr(addr + length)) return NULL; //addr, addr + length not in user address
	if (spt_find_page(&thread_current() -> spt, addr)) return NULL; 
	struct file *f = process_get_file(fd); 
	if (!f) return NULL; 
	if (file_length(f) == 0 || (int) length <= 0) return NULL; 
	return do_mmap(addr, length, writeable, f, offset);
}

/* function to handle memory un map*/
void syscall_munmap(void *addr){
	do_munmap(addr); 
}
#endif

#ifdef EFILESYS
// bool SyS_chdir (const char *dir) {
// 	check_address(dir);

// 	if (strlen(dir) == 0){
// 		return false;
// 	}

// 	return dir_chdir(dir);
// }
bool syscall_chdir(const char *direction){
	// printf("call syscall change dir: %s \n", direction); 
	if (!is_user_vaddr(direction)){
		thread_current() -> exit_status = -1; 
		thread_exit(); 
	}
	if (strlen(direction) == 0){
		return false;
	} 
	return dir_chdir(direction); 
}

bool SyS_mkdir (const char *dir) {
	check_address(dir);
	// printf("system call in make dir: %s \n", dir); 
	return dir_mkdir(dir);
}

bool SyS_readdir (int fd, char *name) {
	check_address(name);

	struct file *file = process_get_file(fd);
	if (file_is_dir(file) == false) {
		return false;
	}
	return dir_readdir((struct dir *) file, name);
}

bool SyS_isdir (int fd) {
	struct file *file = process_get_file(fd);
	return file_is_dir(file);
}

int SyS_inumber (int fd) {
	struct file *file = process_get_file(fd);
	return inode_get_inumber(file_get_inode(file));
}

int SyS_symlink (const char *target, const char *linkpath) {
	check_address(target);
	check_address(linkpath);

	return filesys_symlink(target, linkpath);
}
#endif
// #ifdef EFILESYS 


// bool syscall_mkdir(const char *new_dir){
// 	printf("input direction in make dir: %s \n", new_dir); 
// 	if (!is_user_vaddr(new_dir)){
// 		thread_current() -> exit_status = -1; 
// 		thread_exit(); 
// 	}
// 	if (strlen(new_dir) == 0 || strcmp(new_dir, "/") == 0){
// 		return false;
// 	}
// 	struct dir *pasered_dir = malloc(sizeof(struct dir)); 
// 	char parsered_filename[200]; 
// 	bool res = parser_path_and_file(new_dir, &pasered_dir, parsered_filename); 
// 	printf("parsered file name: %s \n", parsered_filename); 
// 	if (res == false) {
// 		printf("false in parser path and filename \n"); 
// 		return false;
// 	} 
	
// 	struct inode *inode = NULL; 
// 	dir_lookup(pasered_dir, parsered_filename, &inode);
// 	if (inode != NULL) {
// 		inode_close(inode);
// 		dir_close(pasered_dir);
// 		free(parsered_filename);
// 		return false; 
// 	}
// 	disk_sector_t inode_sector = cluster_to_sector(fat_create_chain(0));
// 	bool res_create = dir_create(inode_sector, 0); 
// 	bool res_add = dir_add(pasered_dir, parsered_filename, inode_sector);
// 	if (!res_create && !res_add && inode_sector != 0)
// 		fat_remove_chain(sector_to_cluster(inode_sector), 0);
	
// 	struct dir *final_new_dir = dir_open(inode_open(inode_sector));
// 	dir_add(final_new_dir, ".", inode_sector);
// 	dir_add(final_new_dir, "..", inode_get_inumber(dir_get_inode(pasered_dir)));
// 	dir_close(final_new_dir);

// 	dir_close(pasered_dir);
// 	free(parsered_filename);
// 	return res_create && res_add; 
// }

// bool syscall_readdir(int fd, char *name){
// 	if (!is_user_vaddr(name)){
// 		thread_current() -> exit_status = -1; 
// 		thread_exit(); 
// 	}
// 	struct file *f = process_get_file(fd);
	
// 	if ( !inode_is_dir(file_get_inode(f))) return false; 

// 	return dir_readdir((struct dir *) f, name);
// }

// bool syscall_isdir(int fd){
// 	struct file *file = process_get_file(fd);
// 	return inode_is_dir(file_get_inode(file)); 
// }

// int syscall_inumber(int fd){
// 	struct file *file = process_get_file(fd);
// 	return inode_get_inumber(file_get_inode(file));
// }

// int syscall_symlink(const char *target, const char *linked_path){
// 	if (!is_user_vaddr(target) || !is_user_vaddr(linked_path)){
// 		thread_current() -> exit_status = -1; 
// 		thread_exit(); 
// 	}
// 	struct dir *pasered_dir = malloc(sizeof(struct dir)); 
// 	char parsered_filename[200]; 
	
// 	bool res = parser_path_and_file(target, &pasered_dir, parsered_filename); 
// 	printf("parsered file name: %s \n", parsered_filename); 
// 	if (res == false) {
// 		printf("false in parser path and filename \n"); 
// 		return false;
// 	} 
// }
// #endif
/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
#ifdef VM
	thread_current() -> rsp = f -> rsp; 
#endif
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
			if (!is_user_vaddr (fname)){
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
			// printf("call syscall remove \n"); 
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
			// printf("call open in syscall \n"); 
			f->R.rax = syscall_open (f);
			break;
		case SYS_FILESIZE:
			f->R.rax = syscall_filesize (f);
			break;
		case SYS_READ:
			if (!is_user_vaddr (f -> R.rsi)){
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
			syscall_close (f);
			break;
		case SYS_DUP2:
			f->R.rax = -1;
			break;
#ifdef VM
		case SYS_MMAP:
			f->R.rax = syscall_mmap(f-> R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
			break; 
		case SYS_MUNMAP:
			syscall_munmap(f->R.rdi); 
			break; 
#endif
// #ifdef EFILESYS
// 		case SYS_CHDIR:
// 			f -> R.rax = syscall_chdir(fname);
// 			break; 
// 		case SYS_MKDIR:
// 			f -> R.rax = syscall_mkdir(fname);
// 			break; 
// 		case SYS_READDIR:
// 			f -> R.rax = syscall_readdir(f -> R.rdi, f -> R.rsi);
// 			break; 
// #endif
#ifdef EFILESYS
		case SYS_CHDIR:
			f->R.rax = syscall_chdir(f->R.rdi);
			break;
		case SYS_MKDIR:
			f->R.rax = SyS_mkdir(f->R.rdi);
			break;
		case SYS_READDIR:
			f->R.rax = SyS_readdir(f->R.rdi, f->R.rsi);
			break;
		case SYS_ISDIR:
			f->R.rax = SyS_isdir(f->R.rdi);
			break;
		case SYS_INUMBER:
			f->R.rax = SyS_inumber(f->R.rdi);
			break;
		case SYS_SYMLINK:
			f->R.rax = SyS_symlink(f->R.rdi, f->R.rsi);
			break;
#endif
		default:
			printf ("Unexpected Syscall: %llx", f->R.rax);
			f->R.rax = -1;
			break;
	}
}