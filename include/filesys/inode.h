#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/disk.h"
#include "filesys/fat.h"

struct bitmap;

typedef unsigned char type_t;

enum FTYPE {
    F_INIT,
    F_REG,      /* Regular file */
    F_DIR,      /* Directory */
    F_SYML      /* Softlink (Symlink) */
};

void inode_init (void);
bool inode_create (disk_sector_t, off_t, type_t);
struct inode *inode_open (disk_sector_t);
struct inode *inode_reopen (struct inode *);
disk_sector_t inode_get_inumber (const struct inode *);
void inode_close (struct inode *);
void inode_remove (struct inode *);
off_t inode_read_at (struct inode *, void *, off_t size, off_t offset);
off_t inode_write_at (struct inode *, const void *, off_t size, off_t offset);
void inode_deny_write (struct inode *);
void inode_allow_write (struct inode *);
off_t inode_length (const struct inode *);
int inode_open_cnt (const struct inode *);
bool inode_is_reg (const struct inode *);
bool inode_is_dir (const struct inode *);
bool inode_set_symlink (disk_sector_t inode_sector, const char *target);
bool inode_is_symlink (const struct inode *inode);
char *inode_symlink_path (const struct inode* inode);
char *inode_get_sym_path(const struct inode *inode);

#endif /* filesys/inode.h */
