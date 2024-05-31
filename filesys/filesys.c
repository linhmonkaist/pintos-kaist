#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "devices/disk.h"
#include "filesys/fat.h"
#include "threads/thread.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format (void);

/* Initializes the file system module.
 * If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) {
	filesys_disk = disk_get (0, 1);
	if (filesys_disk == NULL)
		PANIC ("hd0:1 (hdb) not present, file system initialization failed");

	inode_init ();

#ifdef EFILESYS
	fat_init ();

	if (format)
		do_format ();

	fat_open ();

	thread_current()->working_dir = dir_open_root();
#else
	/* Original FS */
	free_map_init ();

	if (format)
		do_format ();

	free_map_open ();
#endif
}

/* Shuts down the file system module, writing any unwritten data
 * to disk. */
void
filesys_done (void) {
	/* Original FS */
#ifdef EFILESYS
	fat_close ();
#else
	free_map_close ();
#endif
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */
#ifdef EFILESYS
bool
filesys_create (const char *name, off_t initial_size) {
	// PANIC("===timeout here===");
	char *file_name = NULL;
	struct dir *dir = NULL;
	disk_sector_t inode_sector = 0;

	if (strlen (name) > NAME_MAX) return false;

	file_name = (char *) malloc(NAME_MAX + 1);
	if (!file_name)
		return false;
	// PANIC("===timeout here===");
	if (!get_fname_from_path(name, file_name)) {
		// Potential problem here in directory --> check here
		// PANIC("===timeout here===");
		free(file_name);
		return false;
	}
	// PANIC("===pass: timeout here===");
	dir = get_dir_from_path(name);
	// printf(dir);
	// Didn't go here
	// PANIC("=== HELLOOOOO timeout here===");

	bool success = (dir != NULL
			&& (inode_sector = cluster_to_sector(fat_create_chain(0)))
			&& inode_create (inode_sector, initial_size, F_REG)
			&& dir_add (dir, file_name, inode_sector));

	// PANIC("=== HELLOOOOO timeout here===");

	if (!success && inode_sector != 0)
		fat_remove_chain(sector_to_cluster(inode_sector), 0);
	// PANIC("=== passsss: HELLOOOOO timeout here===");
	free (file_name);
	dir_close (dir);
	// PANIC("=== pass: HELLOOOOO timeout here===");
	return success;
}
#else
bool
filesys_create (const char *name, off_t initial_size) {
	disk_sector_t inode_sector = 0;
	// struct dir *dir = dir_open_root ();
	bool success = (dir_open_root () != NULL
			&& free_map_allocate (1, &inode_sector)
			&& inode_create (inode_sector, initial_size, F_REG)
			&& dir_add (dir_open_root (), name, inode_sector));
	if (!success && inode_sector != 0)
		free_map_release (inode_sector, 1);
	dir_close (dir_open_root ());

	return success;
}
#endif

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
#ifdef EFILESYS
struct file *
filesys_open (const char *name) {
	struct file *result = NULL;
	char *file_name = NULL;
	struct dir *dir = NULL;
	struct inode *inode = NULL;

	if (strcmp(name, "/") == 0)
		// PANIC("===get_file_name: timeout here===");
		// printf("file name: %s\n", name);
		return dir_open_root();

	// PANIC("===get_file_name: timeout here===");
	file_name = (char *) malloc(NAME_MAX + 1);
	// printf("file name: %s\n", file_name);
	if (!file_name)
		return NULL;

	if (!get_fname_from_path(name, file_name))
		// PANIC("=== no appear - get_fname_from: timeout here===");
		goto free;

	dir = get_dir_from_path(name);
	// PANIC("=== yes appear - get_fname_from: timeout here===");
	if (dir == NULL)
		goto close;

	dir_lookup(dir, file_name, &inode);
	// PANIC("=== yes appear - get_fname_from: timeout here===");
	if (inode == NULL)
		goto close;

	// PANIC("=== yes appear - get_fname_from: timeout here===");
	if (inode_is_symlink(inode))
		result = filesys_open(inode_symlink_path(inode));
		
	else
		result = file_open(inode);

close:
	dir_close(dir);
// 	PANIC("=== yes appear - get_fname_from: timeout here===");
free:
	free(file_name);
	return result;
}
#else
struct file *
filesys_open (const char *name) {
	PANIC("why are you not workingggg");
	struct dir *dir = dir_open_root ();
	struct inode *inode = NULL;

	if (dir != NULL)
		dir_lookup (dir, name, &inode);
	dir_close (dir);

	return file_open (inode);
}
#endif

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
#ifdef EFILESYS
bool
filesys_remove (const char *name) {
	char *temp = NULL;
	char *file_name = NULL;
	struct dir *dir = NULL;

	if (strcmp(name, "/") == 0)
		return false;

	temp = (char *) malloc(strlen(name) + 1);
	if (strlen(name) < NAME_MAX)
		memcpy(temp, name, strlen(name) + 1);
	else
		memcpy(temp, name, NAME_MAX + 1);

	file_name = (char *) malloc(NAME_MAX + 1);
	if (!get_fname_from_path(name, file_name)) {
		free(file_name);
		return false;
	}

	dir = get_dir_from_path(name);

	bool success = dir != NULL && dir_remove (dir, file_name);
	dir_close (dir);

	free(temp);
	free(file_name);

	return success;
}

#else
bool
filesys_remove (const char *name) {
	struct dir *dir = dir_open_root ();
	bool success = dir != NULL && dir_remove (dir, name);
	dir_close (dir);

	return success;
}
#endif

/* Creates a symbolic link named linkpath which contains the string target.
 * Returns 0 if successful, -1 on failure. */
int
filesys_symlink(const char* target, const char* linkpath){
	char *name_file = NULL;
	struct dir *dir = NULL;
	disk_sector_t inode_sector = 0;
	int ret = -1;

	if (target == NULL || linkpath == NULL
		|| strlen(target) == 0
		|| strlen(linkpath)== 0)
		return -1;

	name_file = (char *) malloc(NAME_MAX + 1);
	if (!get_fname_from_path(linkpath, name_file))
		goto free;

	dir = get_dir_from_path(linkpath);
	if (dir == NULL)
		goto close;

	bool succ = ((inode_sector = cluster_to_sector(fat_create_chain(0)))
					&& inode_create(inode_sector, 0, F_SYML)
					&& dir_add(dir, name_file, inode_sector));
	
	if(!succ && inode_sector != 0) {
		fat_remove_chain(sector_to_cluster(inode_sector), 0);
		goto close;
	}

	if (inode_set_symlink(inode_sector, target))
		ret = 0;

close:
	dir_close(dir);
free:
	free(name_file);
	return ret;
}

/* Formats the file system. */
static void
do_format (void) {
	printf ("Formatting file system...");

#ifdef EFILESYS
	/* Create FAT and save it to the disk. */
	fat_create ();

	bool dir_create_succ = dir_create(cluster_to_sector(ROOT_DIR_CLUSTER), 2);
	if (!dir_create_succ){
		PANIC("root directory creation failed");
	}

	fat_close ();

	struct dir *root_dir;
	root_dir = dir_open_root();
	disk_sector_t root_inode_sector = inode_get_inumber(dir_get_inode(root_dir));

	dir_add(root_dir, ".", root_inode_sector);
	dir_add(root_dir, "..", root_inode_sector);

	dir_close(root_dir);
	
#else
	free_map_create ();
	if (!dir_create (ROOT_DIR_SECTOR, 16))
		PANIC ("root directory creation failed");
	free_map_close ();
#endif

	printf ("done.\n");
}
