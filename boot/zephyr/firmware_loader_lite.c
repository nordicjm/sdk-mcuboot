/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2025 Nordic Semiconductor ASA
 */

#include <assert.h>
#include <zephyr/kernel.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/storage/flash_map.h>
#include "bootutil/image.h"
#include "bootutil_priv.h"
#include "bootutil/bootutil_log.h"
#include "bootutil/bootutil_public.h"
#include "bootutil/fault_injection_hardening.h"
#include <bm_installs.h>

#if defined(CONFIG_LITE_SECURE)
#include <litesecure.h>
#endif

#include "io/io.h"
#include "mcuboot_config/mcuboot_config.h"

#define IMAGE_TLV_INSTALLER_IMAGE 0xa0

BOOT_LOG_MODULE_DECLARE(mcuboot);

static struct flash_area fa_app_installer = {
    .fa_id = 1,
    .fa_off = FIXED_PARTITION_OFFSET(slot0_partition),
.fa_size = FIXED_PARTITION_SIZE(slot0_partition), //need to deal with this being dynamic in future
//        .fa_dev = DEVICE_DT_GET(DT_MTD_FROM_FIXED_PARTITION(slot0_partition)),
    .fa_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_flash_controller)),
};

static struct image_header hdr_app_installer = { 0 };

static struct flash_area fa_softdevice = {
    .fa_id = 2,
    .fa_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_flash_controller)),
};

static struct image_header hdr_softdevice = { 0 };

#ifdef CONFIG_BOOT_FIRMWARE_LOADER
static struct flash_area fa_firmware_loader = {
    .fa_id = 3,
    .fa_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_flash_controller)),
};

static struct image_header hdr_firmware_loader = { 0 };
#endif

/**
 * Validate hash of a primary boot image.
 *
 * @param[in]	fa_p	flash area pointer
 * @param[in]	hdr	boot image header pointer
 *
 * @return		FIH_SUCCESS on success, error code otherwise
 */
static fih_ret validate_image(const struct flash_area *fap, struct image_header *hdr)
{
    static uint8_t tmpbuf[BOOT_TMPBUF_SZ];
    FIH_DECLARE(fih_rc, FIH_FAILURE);

    FIH_CALL(bootutil_img_validate, fih_rc, NULL, hdr, fap, tmpbuf, BOOT_TMPBUF_SZ, NULL, 0, NULL);
    FIH_RET(fih_rc);
}

/**
 * Gather information on image and prepare for booting. Will boot from main
 * image if none of the enabled entrance modes for the firmware loader are set,
 * otherwise will boot the firmware loader. Note: firmware loader must be a
 * valid signed image with the same signing key as the application image.
 *
 * @param[out]	rsp	Parameters for booting image, on success
 *
 * @return		FIH_SUCCESS on success; non-zero on failure.
 */
fih_ret
boot_go(struct boot_rsp *rsp)
{
    bool boot_firmware_loader = false;
    FIH_DECLARE(fih_rc, FIH_FAILURE);
    bool softdevice_area_valid = false;
    bool firmware_loader_area_valid = false;
    int rc;
    bool app_installer_image_valid = false;
    bool softdevice_image_valid = false;
    bool firmware_loader_image_valid = false;
    bool app_installer_is_installer_image = false;

#if defined(CONFIG_LITE_SECURE)
    uint32_t protect_start_address = 0;
    uint32_t protect_end_address = 0;
#endif

//add logic here

    bm_installs_init();

    if (bm_installs_isvalid()) {
        off_t start_address = 0;
        size_t image_size = 0;

        rc = bm_installs_get_image_data(BM_INSTALLS_IMAGE_INDEX_SOFTDEVICE, &start_address, &image_size);

        if (!rc) {
            fa_softdevice.fa_off = start_address;
            fa_softdevice.fa_size = image_size;

            if (start_address < fa_app_installer.fa_off) {
//invalid
                goto invalid_softdevice;
            }

            fa_app_installer.fa_size = start_address - fa_app_installer.fa_off;

            rc = boot_image_load_header(&fa_softdevice, &hdr_softdevice);

            if (!rc) {
                softdevice_area_valid = true;
            }
        }

invalid_softdevice:
#ifdef CONFIG_BOOT_FIRMWARE_LOADER
        start_address = 0;
        image_size = 0;
        rc = bm_installs_get_image_data(BM_INSTALLS_IMAGE_INDEX_FIRMWARE_LOADER, &start_address, &image_size);

        if (!rc) {
            fa_firmware_loader.fa_off = start_address;
            fa_firmware_loader.fa_size = image_size;

            if (start_address < fa_app_installer.fa_off) {
//invalid
                goto invalid_firmware_loader;
            }

            fa_app_installer.fa_size = start_address - fa_app_installer.fa_off;

            rc = boot_image_load_header(&fa_firmware_loader, &hdr_softdevice);

            if (!rc) {
                firmware_loader_area_valid = true;
            }
        }
#endif
    }

invalid_firmware_loader:
    rc = boot_image_load_header(&fa_app_installer, &hdr_app_installer);

    if (rc) {
        //todo: error
    }

    FIH_CALL(validate_image, fih_rc, &fa_app_installer, &hdr_app_installer);

    if (FIH_EQ(fih_rc, FIH_SUCCESS)) {
        struct image_tlv_iter it;
        uint32_t off2;
        uint16_t len2;

        app_installer_image_valid = true;

        /**/
        if (hdr_app_installer.ih_protect_tlv_size > 0) {
            rc = bootutil_tlv_iter_begin(&it, &hdr_app_installer, &fa_app_installer, IMAGE_TLV_INSTALLER_IMAGE, true);

            if (rc == 0) {
                /**/
                rc = bootutil_tlv_iter_next(&it, &off2, &len2, NULL);

                if (rc == 0 && len2 == sizeof(app_installer_is_installer_image)) {
                    rc = LOAD_IMAGE_DATA(&hdr_app_installer, &fa_app_installer, off2, &app_installer_is_installer_image, len2);

                    if (rc != 0) {
                        app_installer_is_installer_image = false;
                    }
                }
            }
        }
    }

    if (softdevice_area_valid) {
        fih_rc = FIH_FAILURE;
        rc = boot_image_load_header(&fa_softdevice, &hdr_softdevice);

        if (rc) {
//todo
        }

        FIH_CALL(validate_image, fih_rc, &fa_softdevice, &hdr_softdevice);

        if (FIH_EQ(fih_rc, FIH_SUCCESS)) {
            softdevice_image_valid = true;
        }
    }

#ifdef CONFIG_BOOT_FIRMWARE_LOADER
    if (firmware_loader_area_valid) {
        fih_rc = FIH_FAILURE;
        rc = boot_image_load_header(&fa_firmware_loader, &hdr_firmware_loader);

        if (rc) {
//todo
        }

        FIH_CALL(validate_image, fih_rc, &fa_firmware_loader, &hdr_firmware_loader);

        if (FIH_EQ(fih_rc, FIH_SUCCESS)) {
            firmware_loader_image_valid = true;
        }
    }
#endif

LOG_ERR("app/installer off: 0x%lx, size: 0x%x, type: %d", fa_app_installer.fa_off, fa_app_installer.fa_size, app_installer_is_installer_image);
LOG_ERR("softdevice off: 0x%lx, size: 0x%x", fa_softdevice.fa_off, fa_softdevice.fa_size);
#ifdef CONFIG_BOOT_FIRMWARE_LOADER
LOG_ERR("firmware loader off: 0x%lx, size: 0x%x", fa_firmware_loader.fa_off, fa_firmware_loader.fa_size);
LOG_ERR("softdevice_area_valid: %d, firmware_loader_area_valid: %d, app_installer_image_valid: %d, softdevice_image_valid: %d, firmware_loader_image_valid: %d", softdevice_area_valid, firmware_loader_area_valid, app_installer_image_valid, softdevice_image_valid, firmware_loader_image_valid);
#else
LOG_ERR("softdevice_area_valid: %d, app_installer_image_valid: %d, softdevice_image_valid: %d", softdevice_area_valid, app_installer_image_valid, softdevice_image_valid);
#endif

//    if (FIH_EQ(fih_rc, FIH_SUCCESS)) {
//        FIH_RET(fih_rc);
//    }

//         .fa_off = ,
//         .fa_size = DT_REG_SIZE(part), },

//boot_firmware_loader = true;

#ifdef CONFIG_BOOT_FIRMWARE_LOADER_ENTRANCE_GPIO
    if (io_detect_pin() &&
            !io_boot_skip_serial_recovery()) {
LOG_ERR("a1");
        boot_firmware_loader = true;
    }
#endif

#ifdef CONFIG_BOOT_FIRMWARE_LOADER_PIN_RESET
    if (io_detect_pin_reset()) {
LOG_ERR("a2");
        boot_firmware_loader = true;
    }
#endif

#ifdef CONFIG_BOOT_FIRMWARE_LOADER_BOOT_MODE
    if (io_detect_boot_mode()) {
LOG_ERR("a3");
        boot_firmware_loader = true;
    }
#endif

    if (app_installer_image_valid == true && app_installer_is_installer_image == true) {
//Installer image is present, this gets priority
LOG_ERR("q1");
        rsp->br_image_off = flash_area_get_off(&fa_app_installer);
        rsp->br_hdr = &hdr_app_installer;
//file system only if enabled
#if defined(CONFIG_LITE_SECURE) && defined(FILE_SYSTEM_PARTITION_PRESENT)
        protect_start_address = FILE_SYSTEM_PARTITION_START;
        protect_end_address = FILE_SYSTEM_PARTITION_END;
#endif
    } else if (boot_firmware_loader == true && softdevice_image_valid == true && firmware_loader_image_valid == true) {
//Boot firmware loader
LOG_ERR("q2");
        rsp->br_image_off = flash_area_get_off(&fa_firmware_loader);
        rsp->br_hdr = &hdr_firmware_loader;
#if defined(CONFIG_LITE_SECURE)
        protect_start_address = FIRMWARE_LOADER_PARTITION_START;
        protect_end_address = METADATA_PARTITION_END;
#endif
    } else if (app_installer_image_valid == true && softdevice_image_valid == true) {
//Boot main application
LOG_ERR("q3");
        rsp->br_image_off = flash_area_get_off(&fa_app_installer);
        rsp->br_hdr = &hdr_app_installer;
#if defined(CONFIG_LITE_SECURE)
        protect_start_address = APP_PARTITION_START;
        protect_end_address = METADATA_PARTITION_END;
#endif
    } else if (app_installer_image_valid == false && softdevice_image_valid == true && firmware_loader_image_valid == true) {
//Boot firmware loader due to missing main image
LOG_ERR("q4");
        rsp->br_image_off = flash_area_get_off(&fa_firmware_loader);
        rsp->br_hdr = &hdr_firmware_loader;
#if defined(CONFIG_LITE_SECURE)
        protect_start_address = FIRMWARE_LOADER_PARTITION_START;
        protect_end_address = METADATA_PARTITION_END;
#endif
    } else {
//Cannot boot in this configuration
LOG_ERR("q99");
        return -1;
    }

    rsp->br_flash_dev_id = flash_area_get_device_id(&fa_app_installer);

#if defined(CONFIG_LITE_SECURE)
    if (protect_start_address != 0 || protect_end_address != 0) {
        bool doneit = litesecure_enable(protect_start_address, protect_end_address);
LOG_ERR("apply protection 0x%x - 0x%x = %d", protect_start_address, protect_end_address, doneit);
    }
#endif

return 0;

    FIH_RET(fih_rc);
}
