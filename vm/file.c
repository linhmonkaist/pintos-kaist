/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/mmu.h"
#include "userprog/process.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE, // if file-backed age, invoke this operation
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
	struct lazy_load_arg *lazy_load_arg = (struct lazy_load_arg *) page -> uninit.aux; 
	file_page -> file = lazy_load_arg -> file;
	file_page -> ofs = lazy_load_arg -> ofs; 
	file_page -> read_bytes = lazy_load_arg -> read_bytes; 
	file_page -> zero_bytes = lazy_load_arg -> zero_bytes; 
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	if (pml4_is_dirty(thread_current() -> pml4, page -> va)){
		file_write_at(file_page->file, page -> va, file_page-> read_bytes, file_page -> ofs);
		pml4_set_dirty(thread_current() -> pml4, page -> va, 0);
	}
	pml4_clear_page(thread_current() -> pml4, page -> va); 
}

static bool
lazy_load_segment_file (struct page *page, void *aux) {
	struct lazy_load_arg *lazy_load_arg = (struct lazy_load_arg *)aux;
	
	struct file *file = lazy_load_arg->file;
	off_t ofs = lazy_load_arg->ofs;
	size_t zero_bytes = lazy_load_arg->zero_bytes;
	size_t read_bytes = lazy_load_arg->read_bytes;

	/* Set file position as ofs */
	file_seek(file, ofs);

	/* Read file in physical frame as read_bytes */
	if (file_read(file, page->frame->kva, read_bytes) != (int)(read_bytes))
	{
		palloc_free_page(page->frame->kva);
		return false;
	}

	/* Fill from point of last read with zero_bytes*/
	memset(page->frame->kva + read_bytes, 0, zero_bytes);

	return true;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	struct file *f = file_reopen(file);
	void *start_addr = addr; 
	int total_page_count = length <= PGSIZE ? 1 : length % PGSIZE == 0 ? length / PGSIZE : length /PGSIZE + 1;
	size_t read_bytes = file_length(f) < length ? file_length(f) : length; 
	size_t zero_bytes = pg_round_up(read_bytes) - read_bytes; 
	ASSERT(pg_ofs(offset) == 0);
	ASSERT(offset % PGSIZE == 0);

	while( read_bytes > 0 || zero_bytes > 0){
		size_t page_read_bytes = read_bytes >= PGSIZE ? PGSIZE : read_bytes; 
		size_t page_zero_bytes = PGSIZE - page_read_bytes; 

		struct lazy_load_arg *lazy_load_arg = (struct lazy_load_arg*) malloc(sizeof(struct lazy_load_arg));
		lazy_load_arg -> file = f; 
		lazy_load_arg -> ofs = offset; 
		lazy_load_arg -> read_bytes = page_read_bytes;
		lazy_load_arg -> zero_bytes = page_zero_bytes; 

		bool vm_alloc = vm_alloc_page_with_initializer(VM_FILE, addr, writable, lazy_load_segment_file, lazy_load_arg);

		if (!vm_alloc) return NULL;
		struct page *p = spt_find_page(&thread_current() -> spt, start_addr); 

		p -> mapped_page_count = total_page_count; 

		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		addr += PGSIZE;
		offset += page_read_bytes; 
	}
	return start_addr; 	
}

/* Do the munmap */
void
do_munmap (void *addr) {
	struct supplemental_page_table *spt = &thread_current() -> spt; 
	struct page *p = spt_find_page(spt, addr);
	int count = p -> mapped_page_count; 
	for (int i= 0; i < count; i++){
		if (p) destroy(p);
		addr += PGSIZE;
		p = spt_find_page(spt, addr); 
	}
}
