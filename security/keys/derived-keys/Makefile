# SPDX-License-Identifier: GPL-2.0
#
# Makefile for derived keys
#

obj-$(CONFIG_DERIVED_KEYS) += derived-keys.o
derived-keys-y += derived.o

derived-keys-$(CONFIG_DERIVED_KEYS_SALT_UID_GID) += derived_salt_uid_gid.o
derived-keys-$(CONFIG_DERIVED_KEYS_SALT_FSINFO) += derived_salt_fsinfo.o
derived-keys-$(CONFIG_DERIVED_KEYS_SALT_CSUM) += derived_salt_csum.o

derived-keys-$(CONFIG_DERIVED_KEYS_TPM) += derived_tpm2.o
