/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef H_DECOMPRESSION_
#define H_DECOMPRESSION_

#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include "bootutil/bootutil.h"
#include "bootutil/bootutil_public.h"
#include "bootutil/image.h"
#include "../src/bootutil_priv.h"

#ifdef __cplusplus
extern "C" {
#endif

bool boot_is_compressed_header_valid(const struct image_header *hdr, const struct flash_area *fap, struct boot_loader_state *state);

int boot_copy_region_decompress(struct boot_loader_state *state, const struct flash_area *fap_src,
                                const struct flash_area *fap_dst, uint32_t off_src,
                                uint32_t off_dst, uint32_t sz, uint8_t *buf, size_t buf_size);

int32_t bootutil_get_img_comp_size(const struct image_header *hdr, const struct flash_area *fap,
                                   size_t *img_comp_size);

int bootutil_img_hash_decompress(struct enc_key_data *enc_state, int image_index,
                                 struct image_header *hdr, const struct flash_area *fap,
                                 uint8_t *tmp_buf, uint32_t tmp_buf_sz, uint8_t *hash_result,
                                 uint8_t *seed, int seed_len);

int boot_size_protected_tlvs(const struct image_header *hdr, const struct flash_area *fap_src, uint32_t *sz);

#ifdef __cplusplus
}
#endif

#endif /* H_DECOMPRESSION_ */
