#ifndef IDEVICERESTORE_TURDUS_MERULA_COMMON_H
#define IDEVICERESTORE_TURDUS_MERULA_COMMON_H

#include <stdalign.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include <libfragmentzip/libfragmentzip.h>
#include <plist/plist.h>

#include "../common.h"


#pragma mark - global
void fragmentzip_callback(unsigned int p);

#pragma mark - common
int read_aligned_file_safe(const char* filename, void** data, size_t* size, size_t max_size);
int read_file_safe(const char* filename, void** data, size_t* size, size_t max_size);
uint32_t read_u32_le(const uint8_t *p);
uint64_t read_u64_le(const unsigned char *p);
void write_u32_le(uint8_t *buf, uint32_t value);
void write_u64_le(uint8_t *buf, uint64_t value);
int hexparse(uint8_t *buf, char *s, size_t len);

#pragma mark - idevicerestore
int load_firmware_component_data(const char* path, firmware_component_t* comp, const char* name);
int load_firmware_component_plist(const char* path, firmware_component_t* comp, const char* name);
int get_identity_for_component(struct idevicerestore_client_t* client, firmware_component_t* comp);
int download_component_by_name(fragmentzip_t* fragment, const char* name, const char* altname, firmware_component_t* comp);

int build_identity_get_component_digest(plist_t build_identity, const char* component, uint8_t** buffer, size_t *len);
int check_firmware_components(struct idevicerestore_client_t* client, plist_t build_identity);
int force_get_tss_response(struct idevicerestore_client_t* client, plist_t build_identity, plist_t* tss);
int is_armv7s_soc(uint16_t cpid);

#pragma mark - restore
int recovery_send_ramdisk_component(struct idevicerestore_client_t* client, plist_t build_identity, const char* component);

#pragma mark - dfu
int dfu_get_yolo_checkra1n(struct idevicerestore_client_t* client);
int dfu_get_pwned_dfu(struct idevicerestore_client_t* client);

#endif
