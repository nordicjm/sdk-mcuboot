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
#include "lite/partitions.h"
#include <liteinstalls.h>
#include <fprotect.h>

#include "io/io.h"
#include "mcuboot_config/mcuboot_config.h"

#define IMAGE_TLV_INSTALLER_IMAGE 0xa9

BOOT_LOG_MODULE_DECLARE(mcuboot);

static struct flash_area fa_app_installer = {
    .fa_id = 1,
    .fa_off = APP_PARTITION_START,
.fa_size = APP_PARTITION_SIZE, //need to deal with this being dynamic in future
//        .fa_dev = DEVICE_DT_GET(DT_MTD_FROM_FIXED_PARTITION(slot0_partition)),
    .fa_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_flash_controller)),
};

static struct image_header hdr_app_installer = { 0 };

static struct flash_area fa_softdevice = {
    .fa_id = 2,
    .fa_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_flash_controller)),
};

static struct image_header hdr_softdevice = { 0 };

#ifdef FIRMWARE_LOADER_PARTITION_PRESENT
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
    bool protect_app_installer_area = true;
    bool protect_softdevice = false;
    bool protect_firmware_loader_area = false;
    bool protect_metadata_area = true;

//add logic here

    liteinstalls_init();

    if (liteinstalls_isvalid()) {
        off_t start_address = 0;
        size_t image_size = 0;

        rc = liteinstalls_get_image_data(LISTINSTALLS_IMAGE_INDEX_SOFTDEVICE, &start_address, &image_size);

        if (!rc) {
            fa_softdevice.fa_off = start_address;
            fa_softdevice.fa_size = image_size;

            rc = boot_image_load_header(&fa_softdevice, &hdr_softdevice);

            if (!rc) {
                softdevice_area_valid = true;
            }
        }

#ifdef FIRMWARE_LOADER_PARTITION_PRESENT
        start_address = 0;
        image_size = 0;
        rc = liteinstalls_get_image_data(LISTINSTALLS_IMAGE_INDEX_FIRMWARE_LOADER, &start_address, &image_size);

        if (!rc) {
            fa_firmware_loader.fa_off = start_address;
            fa_firmware_loader.fa_size = image_size;

            rc = boot_image_load_header(&fa_firmware_loader, &hdr_softdevice);

            if (!rc) {
                firmware_loader_area_valid = true;
            }
        }
#endif
    }

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
            protect_softdevice = true;
        }
    }

#ifdef FIRMWARE_LOADER_PARTITION_PRESENT
    if (firmware_loader_area_valid) {
        fih_rc = FIH_FAILURE;
        rc = boot_image_load_header(&fa_firmware_loader, &hdr_firmware_loader);

        if (rc) {
//todo
        }

        FIH_CALL(validate_image, fih_rc, &fa_firmware_loader, &hdr_firmware_loader);

        if (FIH_EQ(fih_rc, FIH_SUCCESS)) {
            firmware_loader_image_valid = true;
            protect_firmware_loader_area = true;
        }
    }
#endif

LOG_ERR("app/installer off: 0x%lx, size: 0x%x, type: %d", fa_app_installer.fa_off, fa_app_installer.fa_size, app_installer_is_installer_image);
LOG_ERR("softdevice off: 0x%lx, size: 0x%x", fa_softdevice.fa_off, fa_softdevice.fa_size);
#ifdef FIRMWARE_LOADER_PARTITION_PRESENT
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
        protect_app_installer_area = false;
        protect_softdevice = false;
        protect_firmware_loader_area = false;
        protect_metadata_area = false;
    } else if (boot_firmware_loader == true && /*softdevice_image_valid == true &&*/ firmware_loader_image_valid == true) {
//Boot firmware loader
LOG_ERR("q2");
        rsp->br_image_off = flash_area_get_off(&fa_firmware_loader);
        rsp->br_hdr = &hdr_firmware_loader;
        protect_app_installer_area = false;
    } else if (app_installer_image_valid == true /*&& softdevice_image_valid == true*/) {
//Boot main application
LOG_ERR("q3");
        rsp->br_image_off = flash_area_get_off(&fa_app_installer);
        rsp->br_hdr = &hdr_app_installer;
    } else if (app_installer_image_valid == false && /*softdevice_image_valid == true &&*/ firmware_loader_image_valid == true) {
//Boot firmware loader due to missing main image
LOG_ERR("q4");
        rsp->br_image_off = flash_area_get_off(&fa_firmware_loader);
        rsp->br_hdr = &hdr_firmware_loader;
        protect_app_installer_area = false;
    } else {
//Cannot boot in this configuration
LOG_ERR("q99");
        return -1;
    }

    rsp->br_flash_dev_id = flash_area_get_device_id(&fa_app_installer);

    if (protect_app_installer_area) {
//todo
        rc = fprotect_area(flash_area_get_off(&fa_app_installer), flash_area_get_size(&fa_app_installer));
LOG_ERR("rcm1 = %d", rc);
    }

    if (protect_softdevice) {
//todo
        rc = fprotect_area(flash_area_get_off(&fa_softdevice), flash_area_get_size(&fa_softdevice));
LOG_ERR("rcm2 = %d", rc);
    }

    if (protect_firmware_loader_area) {
//todo
        rc = fprotect_area(flash_area_get_off(&fa_firmware_loader), flash_area_get_size(&fa_firmware_loader));
LOG_ERR("rcm3 = %d", rc);
    }

    if (protect_metadata_area) {
//todo
        rc = fprotect_area(METADATA_PARTITION_START, METADATA_PARTITION_SIZE);
LOG_ERR("rcm4 = %d", rc);
    }

return 0;

    FIH_RET(fih_rc);
}
