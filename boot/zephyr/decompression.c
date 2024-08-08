/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include "decompression.h"
#include <nrf_compress/implementation.h>

#include "bootutil/bootutil_log.h"
BOOT_LOG_MODULE_DECLARE(mcuboot);

#if !defined(__BOOTSIM__)
#define TARGET_STATIC static
#else
#define TARGET_STATIC
#endif

bool boot_is_compressed_header_valid(struct boot_loader_state *state, uint32_t size)
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

BOOT_LOG_ERR("size: %d, size_check: %d, comp_size: %d", size, size_check, state->compressed_data[BOOT_CURR_IMG(state)].compressed_size);

    if (size >= size_check) {
        return false;
    }

    return true;
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

    write_alignment = flash_area_align(fap_dst);

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

    /* Read in and write compressed data */
    pos = 0;

    while (pos < hdr->ih_img_size) {
        uint32_t copy_size = hdr->ih_img_size - pos;
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

BOOT_LOG_ERR("LAST? pos: %d, tmp_off: %d, chunk %d, compare: %d, img_size: %d", pos, tmp_off, chunk_size, (pos + tmp_off + chunk_size), hdr->ih_img_size);
            if ((pos + tmp_off + chunk_size) >= hdr->ih_img_size) {
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
uint32_t left = sz - hdr->ih_hdr_size - hdr->ih_img_size;// - 2;

    while (pos < left) {
        uint32_t copy_size = left - pos;
        uint32_t write_padding_size;

        if (copy_size > buf_size) {
            copy_size = buf_size;
        }

        /* Read position and write position offsets diverge */
BOOT_LOG_ERR("read from 0x%x for %d", (off_src + hdr->ih_hdr_size + hdr->ih_img_size + pos), copy_size);
        rc = flash_area_read(fap_src, (off_src + hdr->ih_hdr_size + hdr->ih_img_size + pos), buf, copy_size);

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
        rc = flash_area_write(fap_dst, (off_dst + hdr->ih_hdr_size + my_write_pos + pos), buf, (copy_size + write_padding_size));

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
