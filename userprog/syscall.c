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

/* Big lock for filesystem. */
struct lock filesys_lock;

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

static void
error_die (void) {
	thread_current ()->exit_status = -1;
	thread_exit ();
}

static bool
validate_ptr (const void *p, size_t size, bool writable) {
	if (p == NULL || !is_user_vaddr (p))
		return false;
	struct thread *current = thread_current ();
	void *ptr = pg_round_down (p);
	for (; ptr <= pg_round_down (p + size); ptr += PGSIZE) {
		uint64_t *pte = pml4e_walk (current->pml4, (uint64_t) ptr, 0);
		if (pte == NULL ||
				is_kern_pte(pte) ||
				(writable && !is_writable (pte)))
			return false;
	}
	return true;
}

static bool
validate_string (const void *p) {
	if (p == NULL || !is_user_vaddr (p))
		return false;
	struct thread *current = thread_current ();
	void *ptr = pg_round_down (p);
	for (; ; ptr += PGSIZE) {
		uint64_t *pte = pml4e_walk (current->pml4, (uint64_t) ptr, 0);
		if (pte == NULL || is_kern_pte(pte))
			return false;

		for (; *(char *)p != 0; p++);
		if (*(char *)p == 0)
			return true;
	}
}

/* flide manager */
static bool
fd_sort (const struct list_elem *A, const struct list_elem *B, void *_a UNUSED) {
	const struct filde *fdA = list_entry (A, struct filde, elem);
	const struct filde *fdB = list_entry (B, struct filde, elem);

	return fdA->fd < fdB->fd;
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

static int
allocate_fd (void) {
	struct list *fd_list = &thread_current ()->fd_list;
	struct list_elem *e;
	struct filde *filde;
	int32_t __fd = 0;
	for (e = list_begin (fd_list);
			e != list_end (fd_list);
			e = list_next (e), __fd++) {
		filde = list_entry (e, struct filde, elem);
		if (filde->fd != __fd)
			break;
	}
	return __fd;
}

static uint64_t
SyS_fork (struct intr_frame *f) {
	const char *name = (const char *) f->R.rdi;

	if (!validate_string (name))
		error_die ();

	lock_acquire(&filesys_lock);
	tid_t tid = process_fork (name, f);
	lock_release(&filesys_lock);

	return tid;
}

static uint64_t
SyS_exec (struct intr_frame *f) {
	char *fn_copy;
	char *unused;
	const char *fname = (const char *) f->R.rdi;

	if (!validate_string (fname))
		error_die ();

	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		thread_exit ();

	strlcpy (fn_copy, fname, PGSIZE);
	if (strlen(fname) < PGSIZE) {
		fn_copy[strlen(fname) + 1] = 0;
	}
	fn_copy = strtok_r(fn_copy, " ", &unused);

	process_exec (fn_copy);
	NOT_REACHED();
	return -1;
}

static uint64_t
SyS_create (struct intr_frame *f) {
	const char *fname = (const char *) f->R.rdi;
	unsigned initial_size = f->R.rsi;
	int ret;

	if (!validate_string (fname) || !strcmp (fname, ""))
		error_die ();

	lock_acquire (&filesys_lock);
	ret = filesys_create (fname, initial_size);
	lock_release (&filesys_lock);
	return ret;
}

static uint64_t
SyS_remove (struct intr_frame *f) {
	const char *fname = (const char *) f->R.rdi;
	int ret;

	if (!validate_string (fname))
		error_die ();

	lock_acquire (&filesys_lock);
	ret = filesys_remove (fname);
	lock_release (&filesys_lock);
	return ret;
}

static uint64_t
SyS_open (struct intr_frame *f) {
	const char *fname = (const char *) f->R.rdi;
	struct thread *t = thread_current ();
	struct file *file;
	struct filde *filde;
	int fd;
	int ret = -1;

	if (!validate_string (fname))
		error_die ();

	lock_acquire(&filesys_lock);
	fd = allocate_fd ();
	if (fd >= 0) {
		file = filesys_open(fname);
		if (file) {
			filde = (struct filde *) malloc (sizeof (struct filde));
			if (filde) {
				struct file_obj *obj =
					(struct file_obj *) malloc (sizeof (struct file_obj));
				if (obj) {
					ret = fd;
					*obj = (struct file_obj) {
						.file = file,
						.ref_cnt = 1,
					};
					*filde = (struct filde) {
						.fd = ret,
						.obj = obj,
						.type = FILE,
					};
					list_insert_ordered (&t->fd_list, &filde->elem, fd_sort, NULL);
				} else
					free (filde);
			} else
				file_close (file);
		}
	}
	lock_release (&filesys_lock);
	return ret;
}

static uint64_t
SyS_filesize (struct intr_frame *f) {
	int32_t fd = f->R.rdi;
	struct filde *filde;
	int ret = -1;

	lock_acquire (&filesys_lock);
	filde = get_filde_by_fd (fd);
	if (filde)
		ret = file_length (filde->obj->file);
	lock_release (&filesys_lock);
	return ret;
}

static uint64_t
SyS_read (struct intr_frame *f) {
	int fd = f->R.rdi;
	char *buf = (char *) f->R.rsi;
	size_t size = f->R.rdx;
	size_t read_bytes = 0;
	struct filde *filde;
	int ret = -1;

	if (!validate_ptr (buf, size, true))
		error_die ();

	lock_acquire (&filesys_lock);
	filde = get_filde_by_fd (fd);
	if (filde) {
		switch (filde->type) {
			case STDIN:
				for (; read_bytes < size; read_bytes++)
					buf[read_bytes] = input_getc ();
				break;
			case STDOUT:
				ret = -1;
				break;
			default:
				ret = file_read (filde->obj->file, buf, size);
				break;
		}
	}
	lock_release (&filesys_lock);
	return ret;
}

static uint64_t
SyS_write (struct intr_frame *f) {
	int fd = f->R.rdi;
	char *buf = (char *) f->R.rsi;
	size_t size = f->R.rdx;
	struct filde *filde;
	int ret = -1;

	if (!validate_ptr (buf, size, false))
		error_die ();

	lock_acquire (&filesys_lock);
	filde = get_filde_by_fd (fd);
	if (filde) {
		switch (filde->type) {
			case STDIN:
				break;
			case STDOUT:
				putbuf (buf, size);
				ret = size;
				break;
			default:
				ret = file_write (filde->obj->file, buf, size);
				break;
		}
	}
	lock_release (&filesys_lock);
	return ret;
}

static uint64_t
SyS_seek (struct intr_frame *f) {
	int32_t fd = f->R.rdi;
	unsigned position = f->R.rsi;
	struct filde *filde;

	lock_acquire (&filesys_lock);
	filde = get_filde_by_fd (fd);
	if (filde && filde->obj)
		file_seek (filde->obj->file, position);
	lock_release (&filesys_lock);
	return 0;
}

static uint64_t
SyS_tell (struct intr_frame *f) {
	int32_t fd = f->R.rdi;
	struct filde *filde;
	int ret = -1;

	lock_acquire (&filesys_lock);
	filde = get_filde_by_fd (fd);
	if (filde && filde->obj)
		ret = file_tell (filde->obj->file);
	lock_release (&filesys_lock);
	return ret;
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

static uint64_t
SyS_close (struct intr_frame *f) {
	int32_t fd = f->R.rdi;
	return __do_close (fd);
}

static uint64_t
SyS_dup2 (struct intr_frame *f) {
	int32_t oldfd = f->R.rdi;
	int32_t newfd = f->R.rsi;
	struct filde *filde, *new_filde;
	int ret = -1;

	/* Fail if invalid fd */
	if (newfd < 0)
		return ret;

	lock_acquire (&filesys_lock);
	filde = get_filde_by_fd (oldfd);
	new_filde = get_filde_by_fd (newfd);
	if (!filde)
		ret = -1;
	else if (newfd == oldfd)
		ret = newfd;
	else {
		/* close if new_filde is avail. */
		if (new_filde) {
			list_remove (&new_filde->elem);
			clean_filde (new_filde);
		}
		new_filde = (struct filde *) malloc (sizeof (struct filde));
		if (new_filde) {
			*new_filde = *filde;
			new_filde->fd = newfd;
			if (new_filde->obj)
				new_filde->obj->ref_cnt++;

			list_insert_ordered (&thread_current ()->fd_list, &new_filde->elem,
					fd_sort, NULL);
			ret = newfd;
		}
	}
	lock_release (&filesys_lock);
	return ret;
}

// void
// system_exit (int status) {
//   struct thread *curr = thread_current ();
//   curr->exit_status = status;

//   /* TODO: call munmap */
//   printf ("%s: exit(%d)\n", curr->name, curr->exit_status);

//   thread_exit ();
// }

/* Checks if the pointer in the parameter list is valid
Invalid pointers:
1. Pointer points to kernel area
2. Pointers points to invalid address (including NULL), returns page fault */
// void pointer_validator (uint64_t pointer) {
// 	struct thread *curr = thread_current();

// 	//Check if pointer points to kernel area
// 	if (!is_user_vaddr(pointer)){
// 		system_exit(-1);
// 	}
// 	//Check if pointer points to invalid address (inc. NULL)
// 	if (pml4_get_page (curr->pml4, pointer) == NULL || pointer == NULL){
//     	system_exit(-1);
// 	}
// }

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	switch (f->R.rax) {
		case SYS_HALT:
			power_off ();
			// NOT_REACHED ();
			break;
		case SYS_EXIT:
			thread_current ()->exit_status = f->R.rdi;
			thread_exit ();
			// system_exit(f->R.rdi);
			// NOT_REACHED ();
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
			f->R.rax = SyS_seek (f);
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
