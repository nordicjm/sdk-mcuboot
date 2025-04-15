/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2020 Arm Limited
 * Copyright (c) 2020-2025 Nordic Semiconductor ASA
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

#include "io/io.h"
#include "mcuboot_config/mcuboot_config.h"

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
static fih_ret validate_image(const struct flash_area *fa, struct image_header *hdr)
{
    static uint8_t tmpbuf[BOOT_TMPBUF_SZ];
    FIH_DECLARE(fih_rc, FIH_FAILURE);

    /* NOTE: The first argument to boot_image_validate, for enc_state pointer,
     * is allowed to be NULL only because the single image loader compiles
     * with BOOT_IMAGE_NUMBER == 1, which excludes the code that uses
     * the pointer from compilation.
     */
    /* Validate hash */
    if (IS_ENCRYPTED(hdr))
    {
        /* Clear the encrypted flag we didn't supply a key
         * This flag could be set if there was a decryption in place
         * was performed. We will try to validate the image, and if still
         * encrypted the validation will fail, and go in panic mode
         */
        hdr->ih_flags &= ~(ENCRYPTIONFLAGS);
    }

    FIH_CALL(bootutil_img_validate, fih_rc, NULL, hdr, fa, tmpbuf, BOOT_TMPBUF_SZ, NULL, 0, NULL);

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
            rc = bootutil_tlv_iter_begin(&it, &hdr_app_installer, &fa_app_installer, IMAGE_TLV_SEC_CNT, true);

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
        }
    }
#endif

LOG_ERR("app/installer off: %ld, size: %d, type: %d", fa_app_installer.fa_off, fa_app_installer.fa_size, app_installer_is_installer_image);
LOG_ERR("softdevice off: %ld, size: %d", fa_softdevice.fa_off, fa_softdevice.fa_size);
#ifdef FIRMWARE_LOADER_PARTITION_PRESENT
LOG_ERR("firmware loader off: %ld, size: %d", fa_firmware_loader.fa_off, fa_firmware_loader.fa_size);
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
    } else if (boot_firmware_loader == true && /*softdevice_image_valid == true &&*/ firmware_loader_image_valid == true) {
//Boot firmware loader
LOG_ERR("q2");
        rsp->br_image_off = flash_area_get_off(&fa_firmware_loader);
        rsp->br_hdr = &hdr_firmware_loader;
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
    } else {
//Cannot boot in this configuration
LOG_ERR("q99");
        return -1;
    }

//return 0;
    rsp->br_flash_dev_id = flash_area_get_device_id(&fa_app_installer);

return 0;

    FIH_RET(fih_rc);
}
