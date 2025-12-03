#include <linux/module.h>
#include <linux/key-type.h>
#include <keys/user-type.h>

#include "derived.h"

/* inspired by get_mm_exe_file from kernel/fork.c */
struct file *derived_get_current_exe_file(void)
{
	struct mm_struct *mm = current->mm;
	struct file *exe_file;

	if (!mm)
		return NULL;

	rcu_read_lock();
	exe_file = get_file_rcu(&mm->exe_file);
	rcu_read_unlock();
	return exe_file;
}

static int derived_salt_mix_label(struct request_key_auth *rka,
				  struct derived_key_info *info,
				  substring_t param)
{
	if (!param.from || !param.to || param.from > param.to)
		return -EINVAL;

	derived_key_salt_update(info, param.from, param.to - param.from);

	return 0;
}

static int derived_salt_mix_size(struct request_key_auth *rka,
				 struct derived_key_info *info,
				 substring_t param)
{
	int ret;
	if (!param.from || !param.to || param.from > param.to)
		return -EINVAL;

	ret = match_int(&param, &info->size);
	if (ret)
		return ret;

	derived_key_salt_update(info, &info->size, sizeof(info->size));

	return 0;
}

static int derived_salt_mix_err(struct request_key_auth *rka,
				struct derived_key_info *info,
				substring_t param)
{
	return -EINVAL;
}

enum {
	Opt_size,
	Opt_label,
#if IS_ENABLED(CONFIG_DERIVED_KEYS_SALT_UID_GID)
	Opt_uid,
	Opt_gid,
#endif /* CONFIG_DERIVED_KEYS_SALT_UID_GID */
#if IS_ENABLED(CONFIG_DERIVED_KEYS_SALT_FSINFO)
	Opt_path,
	Opt_inode,
	Opt_fsuuid,
#endif /* CONFIG_DERIVED_KEYS_SALT_FSINFO */
#if IS_ENABLED(CONFIG_DERIVED_KEYS_SALT_CSUM)
	Opt_csum,
#endif /* CONFIG_DERIVED_KEYS_SALT_CSUM */
	/* keep Opt_err last */
	Opt_err
};

static const derived_salt_mix_t salt_src_impl[Opt_err + 1] = {
	[Opt_size] = derived_salt_mix_size,
	[Opt_label] = derived_salt_mix_label,
#if IS_ENABLED(CONFIG_DERIVED_KEYS_SALT_UID_GID)
	[Opt_uid] = derived_salt_mix_uid,
	[Opt_gid] = derived_salt_mix_gid,
#endif /* CONFIG_DERIVED_KEYS_SALT_UID_GID */
#if IS_ENABLED(CONFIG_DERIVED_KEYS_SALT_FSINFO)
	[Opt_path] = derived_salt_mix_path,
	[Opt_inode] = derived_salt_mix_inode,
	[Opt_fsuuid] = derived_salt_mix_fsuuid,
#endif /* CONFIG_DERIVED_KEYS_SALT_FSINFO */
#if IS_ENABLED(CONFIG_DERIVED_KEYS_SALT_CSUM)
	[Opt_csum] = derived_salt_mix_csum,
#endif /* CONFIG_DERIVED_KEYS_SALT_CSUM */
	/* keep derived_salt_mix_err last (see Opt_err above) */
	[Opt_err] = derived_salt_mix_err
};

static const match_table_t salt_src_id = {
	{ Opt_size, "size=%d" },
	{ Opt_label, "label=%s" },
#if IS_ENABLED(CONFIG_DERIVED_KEYS_SALT_UID_GID)
	{ Opt_uid, "uid" },
	{ Opt_gid, "gid" },
#endif /* CONFIG_DERIVED_KEYS_SALT_UID_GID */
#if IS_ENABLED(CONFIG_DERIVED_KEYS_SALT_FSINFO)
	{ Opt_path, "path" },
	{ Opt_inode, "inode" },
	{ Opt_fsuuid, "fsuuid" },
#endif /* CONFIG_DERIVED_KEYS_SALT_FSINFO */
#if IS_ENABLED(CONFIG_DERIVED_KEYS_SALT_CSUM)
	{ Opt_csum, "csum" },
#endif /* CONFIG_DERIVED_KEYS_SALT_CSUM */
	{ Opt_err, NULL }
};

static int derived_instantiate(struct key *key,
			       struct key_preparsed_payload *prep)
{
	struct request_key_auth *rka = key->payload.data[1];

	/* return EOPNOTSUPP when userspace tried to create a key via add_key(2) */
	if (!rka)
		return -EOPNOTSUPP;

	/* this should never happen, but just in case? */
	if (rka->target_key != key)
		return -EPERM;

	return generic_key_instantiate(key, prep);
}

static int derived_request_key(struct key *auth_key, void *aux)
{
	struct request_key_auth *rka = get_request_key_auth(auth_key);
	struct key *key = rka->target_key;
	struct derived_key_info *info __free(kfree) =
		kmalloc(sizeof(struct derived_key_info), GFP_KERNEL);
	char *callout_str __free(kfree) =
		kmalloc(rka->callout_len + 1, GFP_KERNEL);
	salt_t salt_res;
	char *p, *c;
	int ret, opt;

	if (!callout_str || !info) {
		complete_request_key(auth_key, -ENOMEM);
		return -ENOMEM;
	}

	memcpy(callout_str, rka->callout_info, rka->callout_len);
	callout_str[rka->callout_len] = 0;
	c = callout_str;

	derived_key_salt_init(info);

	while ((p = strsep(&c, " \t"))) {
		substring_t args[MAX_OPT_ARGS] = { 0 };

		if (*p == '\0' || *p == ' ' || *p == '\t')
			continue;

		opt = match_token(p, salt_src_id, args);
		ret = salt_src_impl[opt](rka, info, args[0]);
		if (ret) {
			complete_request_key(auth_key, ret);
			return ret;
		}
	}

	derived_key_salt_final(info, salt_res);

	if (info->size <= 0) {
		complete_request_key(auth_key, -EINVAL);
		return -EINVAL;
	}

	u8 *payload __free(kfree) = kmalloc(info->size, GFP_KERNEL);
	if (!payload) {
		complete_request_key(auth_key, -ENOMEM);
		return -ENOMEM;
	}

#if IS_ENABLED(CONFIG_DERIVED_KEYS_TPM)
	ret = derived_tpm2_derive(salt_res, sizeof(salt_res), payload,
				  info->size);
	if (ret) {
		complete_request_key(auth_key, ret);
		return ret;
	}
#endif /* CONFIG_DERIVED_KEYS_TPM */

	key->payload.data[1] = rka;
	ret = key_instantiate_and_link(key, payload, info->size,
				       rka->dest_keyring, auth_key);

	complete_request_key(auth_key, ret);
	return ret;
}

static struct key_type key_type_derived = {
	.name = "derived",
	.request_key = derived_request_key,
	.preparse = user_preparse,
	.free_preparse = user_free_preparse,
	.instantiate = derived_instantiate,
	.revoke = user_revoke,
	.destroy = user_destroy,
	.describe = user_describe,
	.read = user_read,
};

static int __init init_derived(void)
{
	int ret;
#if IS_ENABLED(CONFIG_DERIVED_KEYS_TPM)
	ret = derived_tpm2_init();
	if (ret)
		return ret;
#endif /* CONFIG_DERIVED_KEYS_TPM */
	return register_key_type(&key_type_derived);
}

static void __exit cleanup_derived(void)
{
	unregister_key_type(&key_type_derived);
#if IS_ENABLED(CONFIG_DERIVED_KEYS_TPM)
	derived_tpm2_exit();
#endif /* CONFIG_DERIVED_KEYS_TPM */
}

late_initcall(init_derived);
module_exit(cleanup_derived);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Derived Key type");
