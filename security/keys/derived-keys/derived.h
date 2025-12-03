#include <keys/request_key_auth-type.h>
#include <crypto/sha2.h>
#include <linux/parser.h>

struct derived_key_info {
	int size;
	struct sha256_ctx sctx;
};

static inline void derived_key_salt_init(struct derived_key_info *s)
{
	s->size = 0;
	sha256_init(&s->sctx);
}

static inline void derived_key_salt_update(struct derived_key_info *s,
					   const void *data, size_t len)
{
	sha256_update(&s->sctx, data, len);
}

typedef u8 salt_t[SHA256_DIGEST_SIZE];
static inline void derived_key_salt_final(struct derived_key_info *s,
					  salt_t res)
{
	sha256_final(&s->sctx, res);
}

struct file *derived_get_current_exe_file(void);

typedef int (*derived_salt_mix_t)(struct request_key_auth *rka,
				  struct derived_key_info *info,
				  substring_t param);

int derived_salt_mix_uid(struct request_key_auth *rka,
			 struct derived_key_info *info,
			 substring_t param);
int derived_salt_mix_gid(struct request_key_auth *rka,
			 struct derived_key_info *info,
			 substring_t param);
int derived_salt_mix_path(struct request_key_auth *rka,
			  struct derived_key_info *info,
			  substring_t param);
int derived_salt_mix_inode(struct request_key_auth *rka,
			   struct derived_key_info *info,
			   substring_t param);
int derived_salt_mix_fsuuid(struct request_key_auth *rka,
			    struct derived_key_info *info,
			    substring_t param);
int derived_salt_mix_csum(struct request_key_auth *rka,
			  struct derived_key_info *info,
			  substring_t param);

int derived_tpm2_init(void);
void derived_tpm2_exit(void);
int derived_tpm2_derive(const void *salt, size_t salt_len, u8 *out,
			size_t out_len);
