#include "derived.h"
#include "../../drivers/char/tpm/tpm.h"

DEFINE_FREE(tpm_chip_put, struct tpm_chip *, if (_T) tpm_put_ops(_T))
DEFINE_FREE(tpm_buf_free, struct tpm_buf *, if (_T) tpm_buf_destroy(_T))
DEFINE_FREE(tpm_end_auth, struct tpm_chip *, if (_T) tpm2_end_auth_session(_T))

static struct tpm_chip *chip;

static int tpm2_aesctr_create_primary(struct tpm_chip *chip,
				      struct tpm_buf *buf, const void *salt,
				      size_t salt_len, u32 *handle)
{
	off_t handle_offset = TPM_HEADER_SIZE;
	int ret = tpm2_start_auth_session(chip);
	if (ret)
		return ret;

	struct tpm_chip *dev __free(tpm_end_auth) = chip;
	tpm_buf_reset(buf, TPM2_ST_SESSIONS, TPM2_CC_CREATE_PRIMARY);

	/* hierarchy */
	tpm_buf_append_name(dev, buf, TPM2_RH_OWNER, NULL);
	/* hmac TPM session auth, instruct TPM to encrypt the response */
	tpm_buf_append_hmac_session(dev, buf, TPM2_SA_ENCRYPT, NULL, 0);
	/* tpm2 sensitive */
	tpm_buf_append_u16(buf, 4);
	tpm_buf_append_u16(buf, 0);
	tpm_buf_append_u16(buf, 0);
	/* tpm2 public */
	tpm_buf_append_u16(buf,
			   18 + sizeof(TPM2_KERNEL_PRIMARY_PREFIX) - 1 + salt_len);
	tpm_buf_append_u16(buf, TPM_ALG_SYMCIPHER);
	tpm_buf_append_u16(buf, TPM_ALG_SHA256);
	tpm_buf_append_u32(buf, TPM2_OA_FIXED_TPM | TPM2_OA_FIXED_PARENT |
					TPM2_OA_SENSITIVE_DATA_ORIGIN |
					TPM2_OA_USER_WITH_AUTH |
					TPM2_OA_SIGN); /* attr */
	tpm_buf_append_u16(buf, 0); /* auth policy */
	tpm_buf_append_u16(buf, TPM_ALG_AES);
	tpm_buf_append_u16(buf, AES_KEYSIZE_256 * 8);
	tpm_buf_append_u16(buf, TPM_ALG_CTR);
	tpm_buf_append_u16(buf, sizeof(TPM2_KERNEL_PRIMARY_PREFIX) - 1 +
					salt_len); /* unique len */
	tpm_buf_append(buf, TPM2_KERNEL_PRIMARY_PREFIX,
		       sizeof(TPM2_KERNEL_PRIMARY_PREFIX) - 1); /* unique */
	tpm_buf_append(buf, salt, salt_len); /* unique */
	/* outside info */
	tpm_buf_append_u16(buf, 0);
	/* pcr selection */
	tpm_buf_append_u32(buf, 0);

	if (buf->flags & TPM_BUF_OVERFLOW)
		return -E2BIG;

	tpm_buf_fill_hmac_session(chip, buf);
	ret = tpm_transmit_cmd(dev, buf, 0,
			       "attempting to create AES-CTR unique primary");
	ret = tpm_buf_check_hmac_response(dev, buf, ret);
	/* above consumes the auth session */
	retain_and_null_ptr(dev);

	if (ret)
		return tpm_ret_to_err(ret);

	*handle = tpm_buf_read_u32(buf, &handle_offset);

	return 0;
}

static void tpm_buf_append_zeroes(struct tpm_buf *buf, u16 new_length)
{
	if (buf->flags & TPM_BUF_OVERFLOW)
		return;

	if ((buf->length + new_length) > PAGE_SIZE) {
		WARN(1, "tpm_buf: write overflow\n");
		buf->flags |= TPM_BUF_OVERFLOW;
		return;
	}

	memset(&buf->data[buf->length], 0, new_length);
	buf->length += new_length;

	if (buf->flags & TPM_BUF_TPM2B)
		((__be16 *)buf->data)[0] = cpu_to_be16(buf->length - 2);
	else
		((struct tpm_header *)buf->data)->length =
			cpu_to_be32(buf->length);
}

static int tpm2_aesctr_zero_encrypt(struct tpm_chip *chip, struct tpm_buf *buf,
				    u32 handle, u8 *out, size_t len)
{
	off_t offset_r = TPM_HEADER_SIZE;
	size_t cipher_len;
	int ret = tpm2_start_auth_session(chip);
	if (ret)
		return ret;

	struct tpm_chip *dev __free(tpm_end_auth) = chip;

	tpm_buf_reset(buf, TPM2_ST_SESSIONS, TPM2_CC_ENCRYPT_DECRYPT_2);

	/* key handle */
	tpm_buf_append_name(dev, buf, handle, NULL);
	/* hmac TPM session auth, instruct TPM to encrypt the response */
	tpm_buf_append_hmac_session(dev, buf, TPM2_SA_ENCRYPT, NULL, 0);
	/* plaintext */
	tpm_buf_append_u16(buf, len);
	tpm_buf_append_zeroes(buf, len);
	/* yes(1) for decrypt, no(0) for encrypt */
	tpm_buf_append_u8(buf, 0);
	/* symmetric algorithm mode */
	tpm_buf_append_u16(buf, TPM_ALG_CTR);
	/* iv */
	tpm_buf_append_u16(buf, AES_BLOCK_SIZE);
	tpm_buf_append_zeroes(buf, AES_BLOCK_SIZE);

	if (buf->flags & TPM_BUF_OVERFLOW)
		return -E2BIG;

	tpm_buf_fill_hmac_session(chip, buf);
	ret = tpm_transmit_cmd(dev, buf, 0,
			       "attempting to encrypt zeroes with AES-CTR");
	ret = tpm_buf_check_hmac_response(dev, buf, ret);
	/* above consumes the auth session */
	retain_and_null_ptr(dev);

	if (ret)
		return tpm_ret_to_err(ret);

	/* skip total len of the response parameter area */
	tpm_buf_read_u32(buf, &offset_r);
	cipher_len = tpm_buf_read_u16(buf, &offset_r);
	if (cipher_len != len)
		return -EIO;

	if (offset_r + len > buf->length)
		return -E2BIG;

	memcpy(out, &buf->data[offset_r], len);
	return 0;
}

int derived_tpm2_derive(const void *salt, size_t salt_len, u8 *out,
			size_t out_len)
{
	struct tpm_buf buf;
	u32 handle;
	int ret = tpm_try_get_ops(chip);
	if (ret)
		return ret;

	struct tpm_chip *dev __free(tpm_chip_put) = chip;

	ret = tpm_buf_init_sized(&buf);
	if (ret)
		return ret;

	struct tpm_buf *tpmbuf __free(tpm_buf_free) = &buf;

	ret = tpm2_aesctr_create_primary(dev, tpmbuf, salt, salt_len, &handle);
	if (ret)
		return ret;

	ret = tpm2_aesctr_zero_encrypt(dev, tpmbuf, handle, out, out_len);
	tpm2_flush_context(dev, handle);

	return ret;
}

int derived_tpm2_init(void)
{
	chip = tpm_default_chip();
	if (!chip)
		return -ENODEV;

	if (tpm_is_tpm2(chip))
		return 0;

	put_device(&chip->dev);
	chip = NULL;
	return -ENODEV;
}

void derived_tpm2_exit(void)
{
	if (chip)
		put_device(&chip->dev);
}
