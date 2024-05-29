#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "filesys/fat.h"

// /* A directory. */
// struct dir {
// 	struct inode *inode;                /* Backing store. */
// 	off_t pos;                          /* Current position. */
// };

/* A single directory entry. */
struct dir_entry {
	disk_sector_t inode_sector;         /* Sector number of header. */
	char name[NAME_MAX + 1];            /* Null terminated file name. */
	bool in_use;                        /* In use or free? */
};

/* Creates a directory with space for ENTRY_CNT entries in the
 * given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (disk_sector_t sector, size_t entry_cnt) {
	return inode_create (sector, entry_cnt * sizeof (struct dir_entry)); //is_dir set to 1
}

/* Opens and returns the directory for the given INODE, of which
 * it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) {
	struct dir *dir = calloc (1, sizeof *dir);
	if (inode != NULL && dir != NULL) {
		dir->inode = inode;
		dir->pos = 0;
		return dir;
	} else {
		inode_close (inode);
		free (dir);
		return NULL;
	}
}

/* Opens the root directory and returns a directory for it.
 * Return true if successful, false on failure. */
struct dir *
dir_open_root (void) {
	return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
 * Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) {
	return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) {
	if (dir != NULL) {
		inode_close (dir->inode);
		free (dir);
	}
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) {
	return dir->inode;
}

/* Searches DIR for a file with the given NAME.
 * If successful, returns true, sets *EP to the directory entry
 * if EP is non-null, and sets *OFSP to the byte offset of the
 * directory entry if OFSP is non-null.
 * otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
		struct dir_entry *ep, off_t *ofsp) {
	struct dir_entry e;
	size_t ofs;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
			ofs += sizeof e)
		if (e.in_use && !strcmp (name, e.name)) {
			if (ep != NULL)
				*ep = e;
			if (ofsp != NULL)
				*ofsp = ofs;
			return true;
		}
	return false;
}

/* Searches DIR for a file with the given NAME
 * and returns true if one exists, false otherwise.
 * On success, sets *INODE to an inode for the file, otherwise to
 * a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
		struct inode **inode) {
	struct dir_entry e;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	if (lookup (dir, name, &e, NULL))
		*inode = inode_open (e.inode_sector);
	else
		*inode = NULL;

	return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
 * file by that name.  The file's inode is in sector
 * INODE_SECTOR.
 * Returns true if successful, false on failure.
 * Fails if NAME is invalid (i.e. too long) or a disk or memory
 * error occurs. */
bool
dir_add (struct dir *dir, const char *name, disk_sector_t inode_sector) {
	struct dir_entry e;
	off_t ofs;
	bool success = false;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	/* Check NAME for validity. */
	if (*name == '\0' || strlen (name) > NAME_MAX)
		return false;

	/* Check that NAME is not in use. */
	if (lookup (dir, name, NULL, NULL))
		goto done;

	/* Set OFS to offset of free slot.
	 * If there are no free slots, then it will be set to the
	 * current end-of-file.

	 * inode_read_at() will only return a short read at end of file.
	 * Otherwise, we'd need to verify that we didn't get a short
	 * read due to something intermittent such as low memory. */
	for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
			ofs += sizeof e)
		if (!e.in_use)
			break;

	/* Write slot. */
	e.in_use = true;
	strlcpy (e.name, name, sizeof e.name);
	e.inode_sector = inode_sector;
	success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

done:
	return success;
}

/* Removes any entry for NAME in DIR.
 * Returns true if successful, false on failure,
 * which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) {
	struct dir_entry e;
	struct inode *inode = NULL;
	bool success = false;
	off_t ofs;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	/* Find directory entry. */
	if (!lookup (dir, name, &e, &ofs))
		goto done;

	/* Open inode. */
	inode = inode_open (e.inode_sector);
	if (inode == NULL)
		goto done;

	/* Erase directory entry. */
	e.in_use = false;
	if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e)
		goto done;

	/* Remove inode. */
	inode_remove (inode);
	success = true;

done:
	inode_close (inode);
	return success;
}

/* Reads the next directory entry in DIR and stores the name in
 * NAME.  Returns true if successful, false if the directory
 * contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1]) {
	struct dir_entry e;

	while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) {
		dir->pos += sizeof e;
		if (e.in_use) {
			strlcpy (name, e.name, NAME_MAX + 1);
			return true;
		}
	}
	return false;
}

/*get path and open it. Path can be absolute or relative*/
struct dir *get_dir_from_path(const char *path){
	struct dir *current_working_dir = thread_current() -> cur_dir; 
	struct dir *new_dir = NULL; 

	//check the valid of path
	if (strlen(path) ==  0) return NULL; 

	//copy path 
	char *copy_path = malloc(strlen(path) + 1);
	if (!copy_path) return NULL; 

	memcpy(copy_path, path, strlen(path) + 1);  

	//if path is absolute, open the root
	if (copy_path[0] == '/'){
		new_dir = dir_open_root(); 
	} else {
		new_dir = dir_reopen(current_working_dir); 
	}

	//go in each dir of the path and open it with new_dir
	char *temp = NULL; 
	char *token = strtok_r(copy_path, '/', &temp);
	char *cur = strtok_r(NULL, '/', &temp);
	struct inode *inode; 

	while (token != NULL && cur != NULL){
		dir_lookup(new_dir, token, &inode);
		if (inode == NULL) goto fail_no_inode;
		dir_close(new_dir);

		if (inode_is_symlink(inode)){
			char *pointed_path = inode_get_sym_path(inode); 

			new_dir = get_dir_from_path(pointed_path); 
			if (new_dir == NULL) PANIC("symbolic name parser error"); 
			return new_dir; 
		}
		if (!inode_is_dir(inode)) goto fail_close_inode; 
		new_dir = dir_open(inode); 
		token = cur; 
		cur = strtok_r(NULL, '/', &temp);
	}

	return new_dir; 
fail_close_inode: 
	inode_close(inode);
fail_no_inode: 
	free(copy_path);
	dir_close(new_dir);
	return NULL; 
}

/*function to get directory and file/folder in that directory based on the input directory*/
bool parser_path_and_file(const char *input_dir, struct dir *dir, char *filename){
	if (strlen(input_dir) == 0){
		dir = thread_current() -> cur_dir; 
		return true;  
	}

	char *copy_dir = calloc(1, strlen(input_dir) + 1);
	memcpy(copy_dir, input_dir, strlen(input_dir));

	struct dir *current_dir; 
	if (input_dir[0] == '/') current_dir = dir_open_root();
	else current_dir = thread_current() -> cur_dir; 

	struct inode *inode = NULL; 
	char *temp;
	char *token = strtok_r(copy_dir, "/", &temp);
	char *next_token = strtok_r(NULL, "/", &temp); 

	while (token != NULL){
		//if token current is near last -> save file name and return dir, file
		if (next_token == NULL){
			memcpy(filename, token, sizeof(token) + 1);
			return true; 
		}

		//if many dir remains
		dir_lookup(current_dir, token, inode);
		if (inode == NULL) goto fail_no_inode; 
		dir_close(current_dir); 

		if (inode_is_symlink(inode)){
			char *pointed_path = inode_get_sym_path(inode); 

			bool res = parser_path_and_file(pointed_path, current_dir, filename); 
			if (res = false ) PANIC("symbolic name parser error"); 
			return true; 
		}
		if (!inode_is_dir(inode)) goto fail_close_inode; 
		current_dir = dir_open(inode); 
		token = next_token; 
		next_token = strtok_r(NULL, "/" , &temp);
	}

fail_close_inode: 
	inode_close(inode);
fail_no_inode: 
	free(copy_dir);
	dir_close(current_dir);
	return false; 
}