#ifndef IDEVICERESTORE_TURDUS_MERULA_COMMON_H
#define IDEVICERESTORE_TURDUS_MERULA_COMMON_H

#include <stdalign.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include <libfragmentzip/libfragmentzip.h>
#include <plist/plist.h>

#include "../common.h"

typedef struct {
	uint32_t magic;         // 'bsep'
	uint32_t total_size;    // total block size
	uint32_t block_version; // block version
	uint32_t block_size;    // block size
	uint32_t undefined_0;
	uint32_t undefined_1;
	
	uint64_t undefined_2;
	uint16_t undefined_3;
	uint16_t type;          // payload type
	/* ... */
} sep_block_t;
#define BSEP_MAGIC (0x70657362)
#define BSEP_VERSION_1 (1uLL)
#define BSEP_TYPE_NONE (0)
#define BSEP_TYPE_SHC  (1uLL << 0)
#define BSEP_TYPE_PTE  (1uLL << 1)

typedef struct {
	alignas(8) uint32_t magic;
	uint32_t pad0;
	uint64_t type;
	uint64_t fullsize;
	uint64_t datasize;
	uint64_t offset;
	uint64_t tag;
	uint64_t pad1;
} rdsk_bin_t;
#define PLATFORM_FLAG_CPID_8960 (1uLL << 0)
#define PLATFORM_FLAG_CPID_8965 (1uLL << 1)
#define PLATFORM_FLAG_CPID_7000 (1uLL << 2)
#define PLATFORM_FLAG_CPID_7001 (1uLL << 3)
#define PLATFORM_FLAG_CPID_8000 (1uLL << 4)
#define PLATFORM_FLAG_CPID_8003 (1uLL << 5)
#define PLATFORM_FLAG_CPID_8001 (1uLL << 6)
#define PLATFORM_FLAG_CPID_8010 (1uLL << 7)
#define PLATFORM_FLAG_CPID_8011 (1uLL << 8)
#define PLATFORM_FLAG_CPID_8012 (1uLL << 9)
#define PLATFORM_FLAG_CPID_8015 (1uLL << 10)
#define PLATFORM_FLAG_ENV_IOS   (1uLL << 16)
#define PLATFORM_FLAG_ENV_TVOS  (1uLL << 17)
#define IOS_VERSION_FLAG_7      (1uLL << 32)
#define IOS_VERSION_FLAG_8      (1uLL << 33)
#define IOS_VERSION_FLAG_9      (1uLL << 34)
#define IOS_VERSION_FLAG_10     (1uLL << 35)
#define IOS_VERSION_FLAG_11     (1uLL << 36)
#define IOS_VERSION_FLAG_12     (1uLL << 37)
#define IOS_VERSION_FLAG_13     (1uLL << 38)
#define IOS_VERSION_FLAG_14     (1uLL << 39)
#define IOS_VERSION_FLAG_15     (1uLL << 40)
#define IOS_VERSION_FLAG_16     (1uLL << 41)
#define IOS_VERSION_FLAG_17     (1uLL << 42)
#define IOS_VERSION_FLAG_18     (1uLL << 43)
#define IOS_VERSION_FLAG_26     (1uLL << 44)

#define IMG4_DIGEST_ERROR             (0)
#define IMG4_DIGEST_VALID_MANIFEST    (1 << 0)
#define IMG4_DIGEST_MATCHED_MANIFEST  (1 << 1)
#define IMG4_DIGEST_VALID_PAYLOAD     (1 << 2)
#define IMG4_DIGEST_MATCHED_PAYLOAD   (1 << 3)

#pragma mark - common
int read_aligned_file_safe(const char* filename, void** data, size_t* size, size_t max_size);
int read_file_safe(const char* filename, void** data, size_t* size, size_t max_size);
void print_module_hash(const char* name, const uint8_t* buf, const size_t length);
uint32_t read_u32_le(const uint8_t *p);
uint64_t read_u64_le(const unsigned char *p);
void write_u32_le(uint8_t *buf, uint32_t value);
void write_u64_le(uint8_t *buf, uint64_t value);
int hexparse(uint8_t *buf, char *s, size_t len);
bool is_bsep(sep_block_t* bsep);
bool bsep_validate(sep_block_t* bsep);
bool get_bsep_bversion(sep_block_t* bsep, uint32_t* rv);
bool get_bsep_type(sep_block_t* bsep, uint32_t* rv);
uint64_t convert_build_to_ios_vflag(int build_major);
int is_tvos_with_cpid_bdid(uint16_t cpid, uint8_t bdid);
uint64_t convert_cpid_bdid_to_plat_vflag(uint16_t cpid, uint8_t bdid);
int load_rdsk_flag(const uint8_t* bin, size_t bin_len, uint64_t flag, const char* name, uint64_t* out_flag);
int load_module_flag(const uint8_t* bin, size_t bin_len, uint64_t magic, const char* name, uint64_t* out_flag);
int check_vflag(uint64_t flag, uint64_t mask);

#pragma mark - idevicerestore
int load_firmware_component_data(const char* path, firmware_component_t* comp, const char* name);
int load_firmware_component_plist(const char* path, firmware_component_t* comp, const char* name);
int get_identity_for_component(struct idevicerestore_client_t* client, firmware_component_t* comp);
int download_component_by_name(fragmentzip_t* fragment, const char* name, const char* altname, firmware_component_t* comp);

int build_identity_get_component_digest(plist_t build_identity, const char* component, uint8_t** buffer, size_t *len);
int check_firmware_components(struct idevicerestore_client_t* client, plist_t build_identity);
int force_get_tss_response(struct idevicerestore_client_t* client, plist_t build_identity, plist_t* tss);
int is_armv7s_soc(uint16_t cpid);
int is_arm64_soc(uint16_t cpid);
int is_a8_variant_soc(uint16_t cpid);
int is_a9_variant_soc(uint16_t cpid);
int is_a10_variant_soc(uint16_t cpid);
int have_arm64_second_stage_iboot(uint16_t cpid);
int have_arm64_single_stage_iboot(uint16_t cpid);

#pragma mark - img4
void img4_override_payload_tag(const char* component_name, const unsigned char* component_data);
int get_img4_digest_from_manifest(struct idevicerestore_client_t* client, plist_t build_identity, const char *compname, const uint8_t* manifest, const size_t manifest_len, uint8_t** hash, size_t* hash_len);
int get_boot_nonce_hash_from_manifest(struct idevicerestore_client_t* client, const uint8_t* manifest, const size_t manifest_len, uint8_t** boot_nonce_hash, size_t *nonce_hash_length);
int validate_boot_nonce_hash(struct idevicerestore_client_t* client, plist_t tss);
int validate_img4_digest(struct idevicerestore_client_t* client, plist_t build_identity, const char *compname, const uint8_t* payload, const size_t payload_len, const uint8_t* manifest, const size_t manifest_len, bool verify_manifest, bool verify_payload, uint32_t* result);
int get_image4_manifest_hash(const uint8_t* manifest, const size_t manifest_len, uint32_t type, uint8_t** hash, size_t* hash_len);
int validate_ECID(struct idevicerestore_client_t* client, plist_t tss);

#pragma mark - restore
int recovery_send_ramdisk_component(struct idevicerestore_client_t* client, plist_t build_identity, const char* component);
int get_cryptex1_local_cache(struct idevicerestore_client_t* client, plist_t* tss);

#pragma mark - dfu
int dfu_get_yolo_checkra1n(struct idevicerestore_client_t* client);
int dfu_get_pwned_dfu(struct idevicerestore_client_t* client);

#endif
