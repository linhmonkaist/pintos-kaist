/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "userprog/process.h"
#include <hash.h>
#include <string.h>

struct list victim_list; //solution

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init(&victim_list);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		
		struct page *p = (struct page *)malloc(sizeof(struct page));
		if (!p) return false; 

		/* Use a function pointer to pass the corresponding type (since C doesn't have classes or inheritance) */
		bool (*page_initializer)(struct page *, enum vm_type, void *);

		switch (VM_TYPE(type))
        {
        case VM_ANON:
            page_initializer = anon_initializer;
            break;
        case VM_FILE:
            page_initializer = file_backed_initializer;
            break;
		default: 
			PANIC("Invaild vm_type");
			return false; 
        }

		/* Call the uninit_new to initialize the uninit type then make it writable 
		ORDER MATTERS! all writings will be lost if we write before initializing */
		uninit_new(p, upage, init, type, aux, page_initializer);
		p->writable = writable;
		p -> page_vm_type = type; 

		/* TODO: Insert the page into the spt. */
		bool res = spt_insert_page(spt, p);
		if (res){
			p -> owner = thread_current();
			return true; 
		}
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	// struct page *page = NULL;
	// /* TODO: Fill this function. */
	// page = malloc(sizeof(struct page));
    	
	// /* Find va from spt then return the page, else NULL */
	// page->va = pg_round_down(va);
	struct page page;

	page.va = pg_round_down(va);
    struct hash_elem *e = hash_find(&thread_current() ->spt.spt_hash, &page.hash_elem);

	return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
	// return page;
}

/* Insert PAGE into spt with validation. 

Checks if the virtual address does not exist in the given supplemental page table */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	// int succ = false;
	/* TODO: Fill this function. */
	return hash_insert (&spt->spt_hash, &page->hash_elem) == NULL;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */
	struct page *victim_page = list_entry (list_pop_front (&victim_list), struct page, victim_list_elem);
	return victim_page -> frame;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	if (!swap_out(victim->page)) {
		return NULL;
	}

	victim->page = NULL;
	return victim;
	// return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */

	/* Retrieve the physical page from user pool*/
	void *kva = palloc_get_page (PAL_USER);

	// if (kva == NULL) PANIC("todo");

	// /* If kva is null, swap out*/
	if (kva == NULL) {
		frame = vm_evict_frame ();
		return frame;
		// if (!swap_out(frame -> page)) return NULL; 
	} else {
		frame = (struct frame *) malloc (sizeof (struct frame));
		ASSERT (frame != NULL);
		// list_push_back (&frame_list, &frame->frame_elem);
	}
	frame->kva  = kva;
	frame->page = NULL;
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	vm_alloc_page(VM_ANON | VM_MARKER_0, pg_round_down(addr), 1); 
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	//check addr
	if (addr == NULL) return false; 
	if (user && is_kernel_vaddr(addr)) return false; 
	if (!not_present) return false; 
	if (not_present){
		void *rsp = f -> rsp;
		//if kernel access
		if (!user) rsp = thread_current() -> rsp; 

		//if rsp in USER_STACK - 1MB to USER_STACK and address need to access have to point out to current stack pointer and in the range of stack memory
		if (USER_STACK - (1 << 20) <= rsp && rsp <= addr && addr <= USER_STACK) 
			vm_stack_growth(addr); 
		else if (USER_STACK - (1 << 20) <= rsp - 8 && rsp - 8 == addr && addr <= USER_STACK)
			vm_stack_growth(addr);
		
		page = spt_find_page(spt, addr);
		if (page == NULL || (write == 1 && page -> writable == 0))
			{	
				return false; 
			}
		return vm_do_claim_page (page);
	}
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */

	page = spt_find_page(&thread_current()->spt, va);
    if (page == NULL)
        return false;
    
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	bool ret, writable = page->writable;
	struct frame *frame = vm_get_frame ();

	if (frame == NULL){
		PANIC("get null frame \n");
	}

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	/* Basically setup the MMU used for mapping using pml4_set_page*/
	struct thread *current = thread_current();
    bool set_page = pml4_set_page(current->pml4, page->va, frame->kva, page->writable);
	if (!set_page) return false; 
	list_push_back(&victim_list, &page->victim_list_elem);
	return swap_in (page, frame->kva); //for uninit_initialize
}

/* Return the hash value for page p. */
unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED) {
  const struct page *p = hash_entry (p_, struct page, hash_elem);
  return hash_bytes (&p->va, sizeof p->va);
}

/* Returns true if page a precedes page b. */
bool
page_less (const struct hash_elem *a_,
           const struct hash_elem *b_, void *aux UNUSED) {
  const struct page *a = hash_entry (a_, struct page, hash_elem);
  const struct page *b = hash_entry (b_, struct page, hash_elem);

  return a->va < b->va;
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	bool success = hash_init (&spt->spt_hash, page_hash, page_less, NULL);
  	ASSERT (success);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	struct hash_iterator i;
	hash_first(&i, &src->spt_hash);
	while (hash_next(&i))
	{	
		// For src_page
        struct page *src_page = hash_entry(hash_cur(&i), struct page, hash_elem);
        enum vm_type type = src_page->operations->type;
        void *upage = src_page->va;
        bool writable = src_page->writable;

		/* For type UNINIT*/
		if (type == VM_UNINIT)
        { 
            vm_initializer *init = src_page->uninit.init;
			struct lazy_load_arg *aux = (struct lazy_load_arg *) malloc(sizeof(struct lazy_load_arg));
			memcpy(aux, src_page->uninit.aux, sizeof(struct lazy_load_arg));
            bool res= vm_alloc_page_with_initializer(VM_ANON, upage, writable, init, aux);
			if (!res) return false; 
            continue;
        }

		/* For type FILE*/
		if (type == VM_FILE){
			struct lazy_load_arg *file_aux = malloc(sizeof(struct lazy_load_arg));
			file_aux -> file = src_page -> file.file; 
			file_aux -> ofs = src_page -> file.ofs; 
			file_aux->read_bytes = src_page->file.read_bytes;
			file_aux->zero_bytes = src_page->file.zero_bytes;
			file_aux -> is_first_page = src_page -> file.is_first_page;
			file_aux -> num_left_page = src_page -> file.num_left_page;
			bool vm_init = vm_alloc_page_with_initializer(type, upage, writable, NULL, file_aux);
			if (!vm_init) return false; 
			// struct page *file_page = spt_find_page(dst, upage);
			// file_backed_initializer(file_page, type, NULL); 
			// file_page -> frame = src_page -> frame; 
			// pml4_set_page(thread_current() -> pml4, file_page -> va, src_page -> frame -> kva, src_page -> writable);
			continue;
		}
				/* If not type uninit	*/
		if (!vm_alloc_page(VM_ANON | VM_MARKER_0, upage, writable)) 
            return false;

		if (!vm_claim_page(upage))
            return false;

		struct page *dst_page = spt_find_page(dst, upage);
        memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
	}
	return true;
}

void hash_page_destroy(struct hash_elem *e, void *aux)
{
    struct page *page = hash_entry(e, struct page, hash_elem);
    destroy(page);
    free(page);
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_clear(&spt->spt_hash, hash_page_destroy);
}


