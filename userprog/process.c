#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load ( char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);
static struct thread* get_child_tid (tid_t child_tid);

/* General process initializer for initd and other process. */
static void
process_init () {
	struct thread *current = thread_current ();
}


/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	char *copy_to_get_args; 
	char *unused;
	char *save_ptr;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	copy_to_get_args = palloc_get_page (0);
	if (fn_copy == NULL || copy_to_get_args == NULL) 
		return TID_ERROR;

	struct fork_fd *aux =
		(struct fork_fd *) malloc (sizeof (struct fork_fd));

	strlcpy (fn_copy, file_name, PGSIZE);
	strlcpy (copy_to_get_args, file_name, PGSIZE);
	if (strlen(file_name) < PGSIZE) {
		fn_copy[strlen(file_name) + 1] = 0;
	}
	if (strlen(copy_to_get_args) < PGSIZE) {
		copy_to_get_args[strlen(file_name) + 1] = 0;
	}

	fn_copy = strtok_r(fn_copy, " ", &unused);

	/* Create a new thread to execute FILE_NAME. */
	
	aux->file_name = fn_copy;
	aux->parent = thread_current ();

	for (char *token= strtok_r(copy_to_get_args," ", &save_ptr); token != NULL;
	token = strtok_r(NULL, " ", &save_ptr)){
		aux -> arguments_count ++; 
	}
	tid = thread_create (fn_copy, PRI_DEFAULT, initd, aux);
	if (tid == TID_ERROR){
		palloc_free_page (fn_copy);
		palloc_free_page (copy_to_get_args); 
	}
	else{
		struct thread *child = get_child_tid(tid);
		sema_down(&child-> init_sema);
	}
	free (aux);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *input) {
	struct fork_fd *aux = (struct fork_fd *) input;
	char *f_name = aux->file_name;
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();
	thread_current() ->wait_on_exit = true;
	thread_current() ->exit_status = -1;
	sema_up(&thread_current()-> init_sema); 
	if (process_exec (f_name) < 0)
		//make process run
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_ ) {
	struct thread *curr = thread_current ();
	struct fork_fd *fork_temp = calloc (1, sizeof (struct fork_fd));
	
	fork_temp->parent = curr; //set thread to current thread

	memcpy (&curr -> parent_if, if_, sizeof (struct intr_frame)); //copy if_ to if_

	tid_t tid = thread_create (name, PRI_DEFAULT, __do_fork, fork_temp);
	if (tid != TID_ERROR){
		struct thread *child = get_child_tid(tid);  //Mon add 
		sema_down (&child-> fork_sema);

	}
	if (!curr -> fork_succeed){
		tid = TID_ERROR;
	}
		
	free (fork_temp);
	return tid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	if (is_kernel_vaddr (va)) return true;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */

	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	newpage = palloc_get_page (PAL_USER);

	if (newpage == NULL)
		return false;

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	memcpy (newpage, parent_page, PGSIZE);
	writable = is_writable (pte);
	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		palloc_free_page (newpage);
		return false;
	}
	return true;
}
#endif
struct fd_dict {
    int size;
    int i;
    struct entry *entries; // Use a pointer to an array of entries
};

struct entry {
    struct file_obj *parent;
    struct file_obj *child;
};

static struct fd_dict *fd_dict_create(struct list *l) {
    struct fd_dict *fd_dicts = malloc(sizeof(struct fd_dict));
    if (fd_dicts) {
        fd_dicts->size = list_size(l);
        fd_dicts->i = 0;
        fd_dicts->entries = malloc(sizeof(struct entry) * fd_dicts->size);
        if (!fd_dicts->entries) {
            free(fd_dicts); // Ensure no memory leak if entry allocation fails
            return NULL;
        }
    }
    return fd_dicts;
}
static bool fd_dict_insert(struct fd_dict *fd_dict, struct file_obj *p, struct file_obj *c) {
    if (!fd_dict || fd_dict->i >= fd_dict->size) {
        // Log error or handle it more gracefully
        return false;
    }
    fd_dict->entries[fd_dict->i++] = (struct entry){ .parent = p, .child = c };
    return true;
}
static struct file_obj *fd_dict_search(struct fd_dict *fd_dict, struct file_obj *f) {
    if (!fd_dict) return NULL;
    for (int index = 0; index < fd_dict->i; index++) {
        if (fd_dict->entries[index].parent == f)
            return fd_dict->entries[index].child;
    }
    return NULL; 
}

static void free_dict(struct fd_dict *dict){
	free(dict -> entries);
	free(dict);
}

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux_) {
	struct intr_frame if_;
	struct fork_fd *aux = (struct fork_fd *) aux_;
	struct thread *parent = aux->parent;
	struct thread *current = thread_current ();

	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if = &parent -> parent_if;

	bool succ = false;

	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));

	/* 2. Duplicate PT */
	current->exit_status = 0;
	current->pml4 = pml4_create();

	if (current->pml4 == NULL)
		goto error;

	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/
	if_.R.rax = 0;
	struct file_obj *nfile_obj;
	struct filde *filde;
	struct list *fd_list = &parent->fd_list;

	struct fd_dict *dict = fd_dict_create (fd_list);
	if (dict == NULL)
		goto error;

	for (struct list_elem *e = list_begin (fd_list); e != list_end (fd_list); e = list_next (e)) {
		filde = list_entry (e, struct filde, elem);
		struct filde *nfilde = (struct filde *) malloc (sizeof (struct filde));
		if (nfilde == NULL){
			free_dict(dict);
			goto error; 
		}

		nfilde -> fd = filde -> fd;
		nfilde -> elem = filde -> elem;
		nfilde -> obj = filde -> obj;
		if (filde -> fd < 2 ){
			list_push_back (&current->fd_list, &nfilde->elem);
			continue;
		}
		nfile_obj = fd_dict_search (dict, filde->obj);
		if (nfile_obj){
			nfile_obj->ref_cnt++;
			nfilde->obj = nfile_obj;
			list_push_back (&current->fd_list, &nfilde->elem);
			continue;
		}
		nfile_obj = (struct file_obj *) malloc (sizeof (struct file_obj));
		if (nfile_obj == NULL) {
			free(nfilde);
			free_dict(dict);
			goto error; 
		}
		nfile_obj->file = file_duplicate (filde->obj->file);
		nfile_obj->ref_cnt = 0;
		
		if(!fd_dict_insert (dict, filde->obj, nfile_obj)) {
			free(nfile_obj); //Viera Add
			free (nfilde);
			free_dict(dict);
			goto error; 
		}
		nfile_obj->ref_cnt++;
		nfilde->obj = nfile_obj;
		list_push_back (&current->fd_list, &nfilde->elem);
	}

	succ = true;

error:
	parent->fork_succeed = succ; //struct thread *parent = aux->parent;
	char *unuse;
	int args = 0; 
	/* Give control back to the parent */
	process_init ();
	thread_current() -> wait_on_exit = succ;
	if (succ) {
		thread_current() ->exit_status = -1;
	}
	sema_up (&thread_current()-> fork_sema);
	/* Finally, switch to the newly created process. */
	if (succ)
		do_iret (&if_);
	thread_exit ();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *f_name) {
	char *file_name = f_name;
	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup ();

#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	/* And then load the binary */
	success = load (file_name, &_if);

	/* If load failed, quit. */
	palloc_free_page (file_name);
	if (!success) {
		thread_current ()->exit_status = -1;
		thread_exit ();
	}
	/* Start switched process. */
	do_iret (&_if);
	NOT_REACHED ();
}

static struct thread* get_child_tid (tid_t child_tid) {
  struct list *children = &(thread_current ()->childs);
  struct list_elem *e = list_begin (children);
  int cnt_to_child = 0;

  while (e != list_end (children)) {
    struct thread *child_th = list_entry (e, struct thread, child_elem);
    if (child_th->tid == child_tid)
      return child_th;
	cnt_to_child ++; 
	e = list_next (e);
  }
  return NULL;
};


/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid UNUSED) {
	int child_exit_status = -1;
	// struct thread *child = B (thread_current (), child_tid);
	
	struct thread *child = get_child_tid (child_tid);
	/* child doesn't exit and/or dying */
  	if (child == NULL)
    	return child_exit_status;

	//We wait for a child process to exitthen get the exit status
	// else if (child) {
	list_remove (&child->child_elem);
	sema_down (&child->wait_sema);
	child_exit_status = child->exit_status;
	sema_up (&child->cleanup_ok);
	// }
		// return status;
	return child_exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */

	/* Free the file descriptors */
	struct list_elem *e;
	while (!list_empty (&thread_current ()->fd_list)) {
		e = list_pop_front (&thread_current ()->fd_list);
		struct filde *filde = list_entry (e, struct filde, elem); 
		if (filde-> fd > 1){
			struct file_obj *obj = filde -> obj; 
			if (--obj->ref_cnt == 0) {
				file_close (obj->file);
				free (obj);
			}
		}
		free (filde);
	}

	// while (!list_empty (&thread_current ()->childs)) {
	// 	e = list_pop_front (&thread_current ()->childs);
	// 	struct thread *th = list_entry (e, struct thread, child_elem);
	// 	th->wait_on_exit = false;
	// 	sema_up (&th->cleanup_ok);
	// }

	process_cleanup ();

	if (curr->executable)
		file_close (curr->executable);

	if (curr->wait_on_exit) {
		printf ("%s: exit(%d)\n", curr->name, curr->exit_status);
		sema_up (&curr->wait_sema);
		sema_down (&curr->cleanup_ok);
	}
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);
/*argument setup in stack*/
static bool Mon_argument_stack(struct intr_frame *if_, char *file_name){
	int MAX_ARGUMENTS = 64; 
	char *token, *save_ptr; 
	int arg_count = 0; 
	char *arr[MAX_ARGUMENTS];
	uintptr_t arg_address[MAX_ARGUMENTS]; 
	char args_cpy[128];

	memcpy(args_cpy, file_name, strlen(file_name) + 1); 
	for (token = strtok_r(args_cpy, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr)){
		arr[arg_count] = token; 
		arg_count ++; 
	}

	for (int i= arg_count - 1; i > -1; i--){
		if_ -> rsp --;
		*(uint8_t *)if_ -> rsp = (uint8_t) 0;
		for (int c= strlen(arr[i]) -1 ; c > -1; c--){
			if_ -> rsp --; 
			*(uint8_t *)if_ -> rsp = arr[i][c];
		}
		arg_address[arg_count - 1- i] = if_ -> rsp;  
	}
	//padding
	while ( if_ -> rsp % 8){
		if_ -> rsp --; 
		// *(uint8_t **) if_ -> rsp = 0;
	}

	if_ -> rsp -= sizeof(uint64_t);
	*(uint64_t *) if_ -> rsp = (uint64_t) 0;

	for (int i = 0; i < arg_count; i++){
		if_ -> rsp -= sizeof(uint64_t);
		* (uint64_t *) if_ -> rsp =  arg_address[i]; 
	}

	if_ -> R.rdi = arg_count;
	if_ -> R.rsi = if_ -> rsp ; //????     _if.R.rsi = (char *)_if.rsp + 8;
	 
	// if_ -> rsp -= sizeof(uint64_t);
	// *(uint64_t *) if_ -> rsp = (uint64_t) arg_count; 
	if_ -> rsp -= sizeof(uint64_t);
	*(uint64_t *) if_ -> rsp = (uint64_t) 0;

	return true; 
}


/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load ( char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;

	process_activate (thread_current ());

	/* Open executable file. */
	//care about synchronization if someone also open this file 
	file = filesys_open (file_name);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	file_deny_write (file);
	t->executable = file;

	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */
	*(file_name + strlen(file_name)) = ' ';
	Mon_argument_stack(if_, file_name);
	//place argument into stack
	success = true;

done:
	if (!success) {
		file_close (file);
		t->executable = NULL;
	}
	/* We arrive here whether the load is successful or not. */
	return success;
}

// static bool write_one_byte(uint8_t *udst, uint8_t byte){
// 	int error_code; 
// 	asm("movl $1f, %0; movb %b2, %1; 1:" : "=&a" (error_code), "=m" (*udst) : "q" (byte));
// 	return error_code != -1;
// }

// static bool write_four_bytes(uint8_t *udst, )
/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */
