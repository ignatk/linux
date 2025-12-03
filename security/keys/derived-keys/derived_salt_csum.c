#include "derived.h"
#include <linux/ima.h>

int derived_salt_mix_csum(struct request_key_auth *rka,
			  struct derived_key_info *info,
			  substring_t param)
{
	char csum[HASH_MAX_DIGESTSIZE];
	struct file *exe_file __free(fput) = derived_get_current_exe_file();
	int ret;

	if (!exe_file)
		return -ENOENT;

	ret = ima_file_hash(exe_file, csum, sizeof(csum));
	if (ret < 0)
		return ret;

	derived_key_salt_update(info, csum, hash_digest_size[ret]);

	return 0;
}
