#include "derived.h"
#include <linux/mm.h>
#include <linux/file.h>

int derived_salt_mix_path(struct request_key_auth *rka,
			  struct derived_key_info *info,
			  substring_t param)
{
	struct file *exe_file __free(fput) = derived_get_current_exe_file();
	char *path_buf __free(kfree) = NULL;
	char *path;

	if (!exe_file)
		return -ENOENT;

	path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!path_buf)
		return -ENOMEM;

	path = file_path(exe_file, path_buf, PATH_MAX);
	if (IS_ERR(path))
		return PTR_ERR(path);

	derived_key_salt_update(info, path, strlen(path));

	return 0;
}

int derived_salt_mix_inode(struct request_key_auth *rka,
			   struct derived_key_info *info,
			   substring_t param)
{
	struct file *exe_file __free(fput) = derived_get_current_exe_file();
	unsigned long i_ino;

	if (!exe_file)
		return -ENOENT;

	i_ino = file_inode(exe_file)->i_ino;

	derived_key_salt_update(info, &i_ino, sizeof(i_ino));

	return 0;
}

int derived_salt_mix_fsuuid(struct request_key_auth *rka,
			    struct derived_key_info *info,
			    substring_t param)
{
	struct file *exe_file __free(fput) = derived_get_current_exe_file();
	struct super_block *sb;

	if (!exe_file)
		return -ENOENT;

	sb = file_inode(exe_file)->i_sb;

	derived_key_salt_update(info, &sb->s_uuid, sb->s_uuid_len);

	return 0;
}
