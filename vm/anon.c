/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "threads/mmu.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};
static struct args_swap anon_args_swap; //solution

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1,1);
	//solution
	anon_args_swap.swap_table = bitmap_create( disk_size(swap_disk) / 8 ); 

	lock_init(&anon_args_swap.lock_swap);
	//done solution 
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;

	page->anon.swap_table_idx = -1; 
	return true; 
}

/* 
* Swap in the page by read contents from the swap disk. 
* Swaps in an anonymous page from the swap disk by reading the data contents from the disk to memory. 
* The location of the data is the swap disk should have been saved in the page struct when the page was 
* swapped out. Remember to update the swap table
*/
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	size_t idx = anon_page ->swap_table_idx;

	ASSERT(bitmap_test(anon_args_swap.swap_table, idx) == false);
	for (int i=0; i < SECTORS_PER_PAGE; i++){
		disk_read(swap_disk, SECTORS_PER_PAGE * idx + i, kva + i * DISK_SECTOR_SIZE);
	}
	// bitmap_set_multiple(anon_args_swap.swap_table, idx, 1, false); 
	bitmap_set(anon_args_swap.swap_table, idx, 0);
 
	return true; 
}

/* 
* Swap out the page by writing contents to the swap disk. 
* Swaps out an anonymous page to the swap disk by copying the contents from the memory to the disk. 
* First, find a free swap slot in the disk using the swap table, then copy the page of data into the slot. 
* The location of the data should be saved in the page struct. If there is no more free slot in the disk, 
* you can panic the kernel.
*/
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	lock_acquire(&anon_args_swap.lock_swap);
	size_t idx = bitmap_scan_and_flip(anon_args_swap.swap_table, 0, 1, false); 
	lock_release(&anon_args_swap.lock_swap); 
	if (idx == BITMAP_ERROR) 
		PANIC("there is no empty slot left in anon_swap out \n");
	anon_page ->swap_table_idx = idx; 

	for (int i= 0; i < SECTORS_PER_PAGE; i++){
		disk_write(swap_disk, SECTORS_PER_PAGE * idx + i,  page -> frame -> kva + i * DISK_SECTOR_SIZE );
	}

	palloc_free_page (page->frame->kva);
	pml4_clear_page(thread_current() -> pml4, page -> va);
	page -> frame = NULL; 
	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	//solution
	ASSERT(thread_current() == page->owner);

	if (page->frame != NULL){
		free(page->frame);
	}
	
	if (anon_page->aux != NULL){
		free(anon_page->aux);
	}
}
