/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <nrf_compress/implementation.h>
#include "compression/decompression.h"
#include "bootutil/crypto/sha.h"

#include "bootutil/bootutil_log.h"
BOOT_LOG_MODULE_DECLARE(mcuboot);

#if !defined(__BOOTSIM__)
#define TARGET_STATIC static
#else
#define TARGET_STATIC
#endif

bool boot_is_compressed_header_valid(struct boot_loader_state *state, const struct flash_area *fap, uint32_t size)
{
    /* Image is compressed in secondary slot, need to check if fits into the primary slot */
    bool opened_flash_area = false;
    int primary_fa_id;
    int rc;
    int size_check;

    if (BOOT_IMG_AREA(state, BOOT_PRIMARY_SLOT) == NULL) {
        opened_flash_area = true;
    }

    primary_fa_id = flash_area_id_from_multi_image_slot(BOOT_CURR_IMG(state), BOOT_PRIMARY_SLOT);
    rc = flash_area_open(primary_fa_id, &BOOT_IMG_AREA(state, BOOT_PRIMARY_SLOT));
    assert(rc == 0);

    size_check = flash_area_get_size(BOOT_IMG_AREA(state, BOOT_PRIMARY_SLOT));

    if (opened_flash_area) {
        (void)flash_area_close(BOOT_IMG_AREA(state, BOOT_PRIMARY_SLOT));
    }

//TODO
BOOT_LOG_ERR("size: %d, size_check: %d, comp_size: %d", size, size_check, state->compressed_data[BOOT_CURR_IMG(state)].compressed_size);

    if (size >= size_check) {
        return false;
    }

    return true;
}

int bootutil_img_hash_decompress(struct enc_key_data *enc_state, int image_index,
                  struct image_header *hdr, const struct flash_area *fap,
                  uint8_t *tmp_buf, uint32_t tmp_buf_sz, uint8_t *hash_result,
                  uint8_t *seed, int seed_len)
{
//TODO
bootutil_sha_context sha_ctx;
struct image_header modified_hdr;
    int rc;
    uint32_t pos = 0;
    struct nrf_compress_implementation *compression = NULL;
//    TARGET_STATIC uint8_t second_buf[CONFIG_BOOT_DECOMPRESSION_BUFFER_SIZE] __attribute__((aligned(4)));
//uint16_t second_buf_size = 0;
//    uint16_t write_alignment;
//uint32_t my_write_pos = 0;

BOOT_LOG_ERR("hdr size: %d, protected tlv size: %d, img size: %d", hdr->ih_hdr_size, hdr->ih_protect_tlv_size, hdr->ih_img_size);

bootutil_sha_init(&sha_ctx);

    /* Setup decompression system */
#if 0
#if CONFIG_NRF_COMPRESS_LZMA_VERSION_LZMA1
    if (!(hdr->ih_flags & IMAGE_F_COMPRESSED_LZMA1)) {
#elif CONFIG_NRF_COMPRESS_LZMA_VERSION_LZMA2
    if (!(hdr->ih_flags & IMAGE_F_COMPRESSED_LZMA2)) {
#endif
        /* Compressed image does not use the correct compression type which is supported by this build */
//        rc = BOOT_EFLASH;
rc = 4;
        goto finish;
    }
#endif

    compression = nrf_compress_implementation_find(NRF_COMPRESS_TYPE_LZMA);
BOOT_LOG_ERR("find... got %p", compression);

    if (compression == NULL || compression->init == NULL || compression->deinit == NULL || compression->decompress_bytes_needed == NULL || compression->decompress == NULL) {
        /* Compression library missing or missing required function pointer */
//        rc = BOOT_EFLASH;
rc = 4;
        goto finish;
    }

    rc = compression->init(NULL);

    if (rc) {
//        rc = BOOT_EFLASH;
rc = 4;
        goto finish;
    }

//header: replace size with TLV, reduce protected TLV size by size of decompressed image size, remove compressed flags
//protected TLV: remove decompressed image size
//image: decompress
//tlv: ignore, not part of hash

    memcpy(&modified_hdr, hdr, sizeof(modified_hdr));

size_t decompressed_image_size;
rc = bootutil_get_img_comp_size(hdr, fap, &decompressed_image_size);

if (rc) {
rc = 4;
goto finish;
}

    modified_hdr.ih_flags &= ~COMPRESSIONFLAGS;
    modified_hdr.ih_img_size = decompressed_image_size;
    modified_hdr.ih_protect_tlv_size -= 8;
//2 bytes type, 2 bytes length, size of data (4) = 8

//sha of header
bootutil_sha_update(&sha_ctx, &modified_hdr, sizeof(modified_hdr));

//deal with protected TLV part here
pos = 0;

    if (hdr->ih_protect_tlv_size > 0) {
        struct image_tlv_info tlv_header;

        rc = flash_area_read(fap, hdr->ih_hdr_size, &tlv_header, sizeof(tlv_header));

        if (rc) {
            rc = BOOT_EFLASH;
            goto finish;
        }

        tlv_header.it_tlv_tot -= 8;

//sha256 here
bootutil_sha_update(&sha_ctx, &tlv_header, sizeof(tlv_header));

        while (pos < hdr->ih_protect_tlv_size) {
            struct image_tlv tlv_entry_header;

//tmp_buf
//tmp_buf_size
            rc = flash_area_read(fap, hdr->ih_hdr_size + sizeof(tlv_header) + pos, &tlv_entry_header, sizeof(tlv_entry_header));

            if (rc) {
                rc = BOOT_EFLASH;
                goto finish;
            }

            pos += sizeof(tlv_entry_header);

//tlv_entry_header.it_len
            if (tlv_entry_header.it_type == IMAGE_TLV_COMP_SIZE || tlv_entry_header.it_type == IMAGE_TLV_COMP_SHA || tlv_entry_header.it_type == IMAGE_TLV_COMP_SIGNATURE) {
                /* Skip these entries */
                pos += tlv_entry_header.it_len;
                continue;
            }

bootutil_sha_update(&sha_ctx, &tlv_entry_header, sizeof(tlv_entry_header));
uint16_t fizzle = 0;

            while (fizzle < tlv_entry_header.it_len) {
                uint16_t read_size = tmp_buf_sz;

                if ((fizzle + read_size) > tlv_entry_header.it_len) {
                    read_size = tlv_entry_header.it_len - fizzle;
                }

                rc = flash_area_read(fap, hdr->ih_hdr_size + sizeof(tlv_header) + pos + fizzle, tmp_buf, read_size);

                if (rc) {
                    rc = BOOT_EFLASH;
                    goto finish;
                }

//hash here
bootutil_sha_update(&sha_ctx, tmp_buf, read_size);
            }

            pos += tlv_entry_header.it_len;
        }
    }

    /* Read in compressed data, decompress and add to hash calculation */
    pos = 0;

//TODO
    while (pos < hdr->ih_img_size) {
        uint32_t copy_size = hdr->ih_img_size - pos;
        uint32_t tmp_off = 0;

        if (copy_size > tmp_buf_sz) {
            copy_size = tmp_buf_sz;
        }

BOOT_LOG_ERR("read from 0x%x for %d", (hdr->ih_hdr_size + pos), copy_size);
        rc = flash_area_read(fap, hdr->ih_hdr_size + pos, tmp_buf, copy_size);

        if (rc != 0) {
            rc = BOOT_EFLASH;
            goto finish;
        }

        /* Decompress data in chunks, writing it back with a larger write offset of the primary slot than read size of the secondary slot */
        while (tmp_off < copy_size) {
            uint32_t offset = 0;
            uint8_t *output = NULL;
            uint32_t output_size = 0;
uint32_t chunk_size;
            bool last_packet = false;

            chunk_size = compression->decompress_bytes_needed(NULL);

            if (chunk_size > (copy_size - tmp_off)) {
                chunk_size = (copy_size - tmp_off);
            }

BOOT_LOG_ERR("bytes needed: %d", chunk_size);

BOOT_LOG_ERR("LAST? pos: %d, tmp_off: %d, chunk %d, compare: %d, img_size: %d", pos, tmp_off, chunk_size, (pos + tmp_off + chunk_size), hdr->ih_img_size);
            if ((pos + tmp_off + chunk_size) >= hdr->ih_img_size) {
                last_packet = true;
            }

            rc = compression->decompress(NULL, &tmp_buf[tmp_off], chunk_size, last_packet, &offset, &output, &output_size);

BOOT_LOG_ERR("rc = %d, dat in = %02x %02x, offset = %d, output size = %d, buffer = %p, last = %d", rc, tmp_buf[tmp_off], tmp_buf[tmp_off + 1], tmp_off, output_size, output, last_packet);

            if (rc) {
//                rc = BOOT_EFLASH;
rc = -4;
                goto finish;
            }

//TODO: should only be checked in the dry run
#if 0
            if (last_packet == true && (my_write_pos + output_size) == 0) {
                /* Last packet and we still have no output, this is a faulty update */
//                rc = BOOT_EFLASH;
rc = -3;
                goto finish;
            }
#endif

            if (offset == 0) {
//TODO: if this happens over and over, error, though only check in dry run
                break;
            }

            /* Copy data to secondary buffer for writing out */
            if (output_size > 0) {
//hash data here
bootutil_sha_update(&sha_ctx, output, output_size);
            }

            tmp_off += chunk_size;
        }

        pos += copy_size;
    }

    /* Clean up decompression system */
    (void)compression->deinit(NULL);

//finish hash here
    bootutil_sha_finish(&sha_ctx, hash_result);
    bootutil_sha_drop(&sha_ctx);

BOOT_LOG_ERR("success?");
finish:

    return 0;
}


// *sz will be updated with length of new section
static int boot_copy_protected_tlvs(struct image_header *hdr, const struct flash_area *fap_src, 
const struct flash_area *fap_dst, uint32_t off_src, uint32_t off_dst, uint32_t *sz, uint8_t *buf, size_t buf_size)
{
    int rc;
    uint32_t pos = 0;
    uint32_t tlv_size = 0;
    uint32_t off;
    uint16_t len;
    uint16_t type;
    struct image_tlv_iter it;
    struct image_tlv tlv_header;
    struct image_tlv_info tlv_info_header;

    *sz = 0;

//Skip header
pos = sizeof(tlv_info_header);

    rc = bootutil_tlv_iter_begin(&it, hdr, fap_src, IMAGE_TLV_ANY, true);
    if (rc) {
        goto out;
    }

//    if (it.tlv_end > bootutil_max_image_size(fap)) {
//        rc = -1;
//        goto out;
//    }

    while (true) {
        rc = bootutil_tlv_iter_next(&it, &off, &len, &type);
        if (rc < 0) {
            goto out;
        } else if (rc > 0) {
            break;
        }

        if (type == IMAGE_TLV_COMP_SIZE || type == IMAGE_TLV_COMP_SHA || type == IMAGE_TLV_COMP_SIGNATURE) {
            //Skip these TLVs as they are not needed
LOG_ERR("skip type %d", type);
        } else {
            uint32_t copy_done = 0;
uint32_t copy_buffer_pos;

            tlv_header.it_type = type;
            tlv_header.it_len = len;
            memcpy(buf, &tlv_header, sizeof(tlv_header));
            tlv_size += sizeof(tlv_header) + len;

copy_buffer_pos = sizeof(tlv_header);

            while (copy_done < tlv_header.it_len) {
                uint32_t copy_size = buf_size - copy_buffer_pos;
                uint32_t write_size;

                if ((copy_size + copy_done) > tlv_header.it_len) {
                    copy_size = tlv_header.it_len - copy_done;
                }

                write_size = copy_size;
                rc = LOAD_IMAGE_DATA(hdr, fap_src, (off + copy_done), &buf[copy_buffer_pos], copy_size);

//deal with minimum write size here

                if ((copy_size % 4) != 0) {
                    uint8_t padding = 4 - (copy_size % 4);

                    memset(&buf[copy_size], 0xff, padding);
                    write_size += padding;
                }

//write to destination
LOG_ERR("write1 %d to %d", write_size, (off_dst + pos));
    rc = flash_area_write(fap_dst, (off_dst + pos), buf, write_size);
    if (rc != 0) {
        rc = BOOT_EFLASH;
goto out;
    }

LOG_ERR("tlv type %d, len %d, copy size %d, copy_buffer_pos %d, tlv size %d, write_size %d, write address %d", type, len, copy_size, copy_buffer_pos, tlv_size, write_size, (off_dst + pos));

                copy_done += copy_size;
                copy_buffer_pos = 0;
                pos += copy_size;
            }
/* */

        }
    }

LOG_ERR("total tlv size %d", tlv_size);
    if (tlv_size > 0) {
//Write header
        tlv_info_header.it_magic = IMAGE_TLV_PROT_INFO_MAGIC;
        tlv_info_header.it_tlv_tot = tlv_size + sizeof(tlv_info_header);

//write to destination
LOG_ERR("write2 %d to %d", sizeof(tlv_info_header), off_dst);
    rc = flash_area_write(fap_dst, off_dst, &tlv_info_header, sizeof(tlv_info_header));
    if (rc != 0) {
        rc = BOOT_EFLASH;
goto out;
    }

        *sz = tlv_info_header.it_tlv_tot;

LOG_ERR("tlv info header size %d, write to 0 of %d", *sz, sizeof(tlv_info_header));
    }

out:
if (rc) {
LOG_ERR("uh oh %d", rc);
}
    return 0;
}

static int boot_copy_unprotected_tlvs()
{
}


int boot_copy_region_decompress(struct boot_loader_state *state,
                 const struct flash_area *fap_src,
                 const struct flash_area *fap_dst,
                 uint32_t off_src, uint32_t off_dst, uint32_t sz, uint8_t *buf, size_t buf_size)
{
    int rc;
    struct image_header *hdr;
    uint32_t pos = 0;
    struct nrf_compress_implementation *compression = NULL;
    TARGET_STATIC uint8_t second_buf[CONFIG_BOOT_DECOMPRESSION_BUFFER_SIZE] __attribute__((aligned(4)));
uint16_t second_buf_size = 0;
    uint16_t write_alignment;
uint32_t my_write_pos = 0;

    hdr = boot_img_hdr(state, BOOT_SECONDARY_SLOT);

BOOT_LOG_ERR("hdr size: %d, protected tlv size: %d, img size: %d", hdr->ih_hdr_size, hdr->ih_protect_tlv_size, hdr->ih_img_size);

    /* Setup decompression system */
#if CONFIG_NRF_COMPRESS_LZMA_VERSION_LZMA1
    if (!(hdr->ih_flags & IMAGE_F_COMPRESSED_LZMA1)) {
#elif CONFIG_NRF_COMPRESS_LZMA_VERSION_LZMA2
    if (!(hdr->ih_flags & IMAGE_F_COMPRESSED_LZMA2)) {
#endif
        /* Compressed image does not use the correct compression type which is supported by this build */
//        rc = BOOT_EFLASH;
rc = 4;
        goto finish;
    }

    compression = nrf_compress_implementation_find(NRF_COMPRESS_TYPE_LZMA);
BOOT_LOG_ERR("find... got %p", compression);

    if (compression == NULL || compression->init == NULL || compression->deinit == NULL || compression->decompress_bytes_needed == NULL || compression->decompress == NULL) {
        /* Compression library missing or missing required function pointer */
//        rc = BOOT_EFLASH;
rc = 4;
        goto finish;
    }

    rc = compression->init(NULL);

    if (rc) {
//        rc = BOOT_EFLASH;
rc = 4;
        goto finish;
    }

    write_alignment = flash_area_align(fap_dst);

//TODO:
//deal with protected TLVs first, removing ones that are not needed, store total size, write out to new slot
//deal with decompressing image data, write out
//deal with unprotected TLVs, write out
//deal with headers, adjust protected TLV size, adjust image size, remove compressed flag, write out

uint32_t protected_tlv_size = 0;
rc = boot_copy_protected_tlvs(hdr, fap_src, fap_dst, off_src, (off_dst + hdr->ih_hdr_size + 0x5a64), &protected_tlv_size, buf, buf_size);

//hack
uint32_t orig_size = hdr->ih_img_size;
uint32_t orig_tlv_offset = hdr->ih_protect_tlv_size;
hdr->ih_protect_tlv_size = protected_tlv_size;
hdr->ih_flags = 0;
hdr->ih_img_size = 0x5a64; //get from tlv

//header?
        rc = flash_area_write(fap_dst, off_dst + pos, hdr, sizeof(*hdr));

        if (rc != 0) {
            rc = BOOT_EFLASH;
            goto finish;
        }

pos += sizeof(*hdr);

#if 0
    /* Copy image header */
    while (pos < hdr->ih_hdr_size) {
        uint32_t copy_size = hdr->ih_hdr_size - pos;

        if (copy_size > buf_size) {
            copy_size = buf_size;
        }

BOOT_LOG_ERR("read from 0x%x for %d", (off_src + pos), copy_size);
        rc = flash_area_read(fap_src, off_src + pos, buf, copy_size);
LOG_HEXDUMP_ERR(buf, copy_size, "read");

        if (rc != 0) {
            rc = BOOT_EFLASH;
            goto finish;
        }

        /* This assumes that the flash write size is compatible with the image header size */
BOOT_LOG_ERR("write to 0x%x for %d", (off_dst + pos), copy_size);
        rc = flash_area_write(fap_dst, off_dst + pos, buf, copy_size);

        if (rc != 0) {
            rc = BOOT_EFLASH;
            goto finish;
        }

        pos += copy_size;
    }
#endif

//TODO: protected TLVs

    /* Read in and write compressed data */
    pos = 0;

    while (pos < orig_size) {
        uint32_t copy_size = orig_size - pos;
        uint32_t tmp_off = 0;

        if (copy_size > buf_size) {
            copy_size = buf_size;
        }

BOOT_LOG_ERR("read from 0x%x for %d", (off_src + hdr->ih_hdr_size + pos), copy_size);
        rc = flash_area_read(fap_src, off_src + hdr->ih_hdr_size + pos, buf, copy_size);

        if (rc != 0) {
            rc = BOOT_EFLASH;
            goto finish;
        }

        /* Decompress data in chunks, writing it back with a larger write offset of the primary slot than read size of the secondary slot */
        while (tmp_off < copy_size) {
            uint32_t offset = 0;
            uint8_t *output = NULL;
            uint32_t output_size = 0;
uint32_t chunk_size;
            bool last_packet = false;

//TODO: make this function unsigned
            chunk_size = compression->decompress_bytes_needed(NULL);

//            if (rc <= 0) {
//return -4;
//            }

            if (chunk_size > (copy_size - tmp_off)) {
                chunk_size = (copy_size - tmp_off);
            }

BOOT_LOG_ERR("bytes needed: %d", chunk_size);

BOOT_LOG_ERR("LAST? pos: %d, tmp_off: %d, chunk %d, compare: %d, img_size: %d", pos, tmp_off, chunk_size, (pos + tmp_off + chunk_size), orig_size);
            if ((pos + tmp_off + chunk_size) >= orig_size) {
                last_packet = true;
            }

            rc = compression->decompress(NULL, &buf[tmp_off], chunk_size, last_packet, &offset, &output, &output_size);

BOOT_LOG_ERR("rc = %d, dat in = %02x %02x, offset = %d, output size = %d, buffer = %p, last = %d", rc, buf[tmp_off], buf[tmp_off + 1], tmp_off, output_size, output, last_packet);

            if (rc) {
//                rc = BOOT_EFLASH;
rc = -4;
                goto finish;
            }

//TODO: should only be checked in the dry run
            if (last_packet == true && (my_write_pos + output_size) == 0) {
                /* Last packet and we still have no output, this is a faulty update */
//                rc = BOOT_EFLASH;
rc = -3;
                goto finish;
            }

            if (offset == 0) {
//TODO: if this happens over and over, error, though only check in dry run
                break;
            }

            /* Copy data to secondary buffer for writing out */
            while (output_size > 0) {
                uint32_t data_size = (sizeof(second_buf) - second_buf_size);

                if (data_size > output_size) {
                    data_size = output_size;
                }

BOOT_LOG_ERR("data size = %d", data_size);
                memcpy(&second_buf[second_buf_size], output, data_size);
                memmove(output, &output[data_size], output_size - data_size);

                second_buf_size += data_size;
                output_size -= data_size;

                /* Write data out from secondary buffer when it is full */
                if (second_buf_size == sizeof(second_buf)) {
BOOT_LOG_ERR("write to 0x%x", (off_dst + hdr->ih_hdr_size + my_write_pos));
LOG_HEXDUMP_ERR(second_buf, sizeof(second_buf), "write");


#ifdef MCUBOOT_ENC_IMAGES
                    if (IS_ENCRYPTED(hdr)) {
                        boot_encrypt(BOOT_CURR_ENC(state), image_index, fap_src, (off_dst + hdr->ih_hdr_size + my_write_pos), sizeof(second_buf), 0, second_buf);
                    }
#endif

                    rc = flash_area_write(fap_dst, (off_dst + hdr->ih_hdr_size + my_write_pos), second_buf, sizeof(second_buf));

                    if (rc != 0) {
                        rc = BOOT_EFLASH;
                        goto finish;
                    }

                    my_write_pos += sizeof(second_buf);
                    second_buf_size = 0;
                }
            }

            tmp_off += chunk_size;
        }

        pos += copy_size;
    }

    if (second_buf_size > 0) {
        /* Write out rest of buffer */
        uint32_t write_padding_size = second_buf_size % write_alignment;

#ifdef MCUBOOT_ENC_IMAGES
        if (IS_ENCRYPTED(hdr)) {
            boot_encrypt(BOOT_CURR_ENC(state), image_index, fap_src, (off_dst + hdr->ih_hdr_size + my_write_pos), second_buf_size, 0, second_buf);
        }
#endif

        /* Check if additional write padding should be applied to meet the minimum write size */
        if (write_padding_size) {
            memset(&second_buf[second_buf_size], 0xff, write_padding_size);
            second_buf_size += write_padding_size;
        }

BOOT_LOG_ERR("write to 0x%x for %d", (off_dst + hdr->ih_hdr_size + my_write_pos), second_buf_size);
LOG_HEXDUMP_ERR(second_buf, second_buf_size, "write");
        rc = flash_area_write(fap_dst, (off_dst + hdr->ih_hdr_size + my_write_pos), second_buf, second_buf_size);

        if (rc != 0) {
            rc = BOOT_EFLASH;
            goto finish;
        }

        my_write_pos += second_buf_size;
        second_buf_size = 0;
    }

    /* Clean up decompression system */
    (void)compression->deinit(NULL);

    /* Copy image trailer */
BOOT_LOG_ERR("footer... 0x%x of 0x%x", pos, sz);
    pos = 0;
//WHY IS THERE A 2 DISCREPENCY??
uint32_t left = sz - hdr->ih_hdr_size - orig_size;// - 2;

    while (pos < left) {
        uint32_t copy_size = left - pos;
        uint32_t write_padding_size;

        if (copy_size > buf_size) {
            copy_size = buf_size;
        }

        /* Read position and write position offsets diverge */
BOOT_LOG_ERR("read from 0x%x for %d", (off_src + hdr->ih_hdr_size + orig_size + orig_tlv_offset + pos), copy_size);
        rc = flash_area_read(fap_src, (off_src + hdr->ih_hdr_size + orig_size + orig_tlv_offset + pos), buf, copy_size);

        if (rc) {
            rc = BOOT_EFLASH;
            goto finish;
        }

        /* Check if additional write padding should be applied to meet the minimum write size */
        write_padding_size = copy_size % write_alignment;

        if (write_padding_size) {
            memset(&buf[copy_size], 0xff, write_padding_size);
        }
BOOT_LOG_ERR("write to 0x%x for %d", (off_dst + hdr->ih_hdr_size + my_write_pos + pos), copy_size);
LOG_HEXDUMP_ERR(buf, copy_size, "write");
        rc = flash_area_write(fap_dst, (off_dst + hdr->ih_hdr_size + hdr->ih_protect_tlv_size + my_write_pos + pos), buf, (copy_size + write_padding_size));

        if (rc) {
            rc = BOOT_EFLASH;
            goto finish;
        }

        pos += copy_size;
    }

BOOT_LOG_ERR("success?");
finish:

    memset(second_buf, 0, sizeof(second_buf));

    return 0;
}

int32_t bootutil_get_img_comp_size(struct image_header *hdr,
                           const struct flash_area *fap,
                           size_t *img_comp_size)
{
    struct image_tlv_iter it;
    uint32_t off;
    uint16_t len;
    int32_t rc;

    if ((hdr == NULL) ||
        (fap == NULL) ||
        (img_comp_size == NULL)) {
        /* Invalid parameter. */
        return BOOT_EBADARGS;
    }

    /* The security counter TLV is in the protected part of the TLV area. */
//    if (hdr->ih_protect_tlv_size == 0) {
//        return BOOT_EBADIMAGE;
//    }

    rc = bootutil_tlv_iter_begin(&it, hdr, fap, IMAGE_TLV_COMP_SIZE, true);
BOOT_LOG_ERR("begin...");
//    rc = bootutil_tlv_iter_begin(&it, hdr, fap, IMAGE_TLV_COMP_SIZE, false);
    if (rc) {
        return rc;
    }

    /* Traverse through the protected TLV area to find
     * the security counter TLV.
     */

    rc = bootutil_tlv_iter_next(&it, &off, &len, NULL);
    if (rc != 0) {
        /* Security counter TLV has not been found. */
        return -1;
    }

BOOT_LOG_ERR("len... %d", len);
    if (len != sizeof(*img_comp_size)) {
        /* Security counter is not valid. */
        return BOOT_EBADIMAGE;
    }

    rc = LOAD_IMAGE_DATA(hdr, fap, off, img_comp_size, len);
    if (rc != 0) {
        return BOOT_EFLASH;
    }

BOOT_LOG_ERR("end... %d", *img_comp_size);

    return 0;
}