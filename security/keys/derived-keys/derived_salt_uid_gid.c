#include "derived.h"
#include <linux/cred.h>

int derived_salt_mix_uid(struct request_key_auth *rka,
			 struct derived_key_info *info, substring_t param)
{
	derived_key_salt_update(info, &rka->cred->uid,
				sizeof(rka->cred->uid));

	return 0;
}

int derived_salt_mix_gid(struct request_key_auth *rka,
			 struct derived_key_info *info, substring_t param)
{
	derived_key_salt_update(info, &rka->cred->gid,
				sizeof(rka->cred->gid));

	return 0;
}
