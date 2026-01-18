#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <libgen.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <libimobiledevice-glue/thread.h>
#include <libimobiledevice-glue/collection.h>
#include <libirecovery.h>
#include <libtatsu/tss.h>
#include <plist/plist.h>

#include <libimobiledevice-glue/sha.h>
#include <libDER/libDER_config.h>
#include <libDER/libDER.h>
#include <libDER/DER_Decode.h>
#include <libDER/DER_Encode.h>
#include <libDER/asn1Types.h>
#if (__linux__)
#include <arpa/inet.h>
#endif

#include <zlib.h>
#include "../common.h"
#include "../endianness.h"
#include "../dfu.h"
#include "../img4.h"
#include "../recovery.h"
#include "../restore.h"
#include "../normal.h"
#include "merula.h"

#ifdef HAVE_LIBHFSPLUS
#include "../libhfsplus/hfs_patch_asr.h"
#endif

#pragma mark - common
int read_file_safe(const char* filename, void** data, size_t* size, size_t max_size)
{
	size_t bytes = 0;
	size_t length = 0;
	FILE* file = NULL;
	char* buffer = NULL;
	struct stat fst;
	
	logger(LL_DEBUG, "Reading data from %s\n", filename);
	
	*size = 0;
	*data = NULL;
	
	file = fopen(filename, "rb");
	if (file == NULL) {
		logger(LL_ERROR, "read_file: cannot open %s: %s\n", filename, strerror(errno));
		return -1;
	}
	
	if (fstat(fileno(file), &fst) < 0) {
		logger(LL_ERROR, "read_file: fstat: %s\n", strerror(errno));
		fclose(file);
		return -1;
	}
	if (fst.st_size < 0) {
		logger(LL_ERROR, "Invalid file size\n");
		fclose(file);
		return -1;
	}
	length = (size_t)fst.st_size;
	if (length == 0 || length > max_size) {
		logger(LL_ERROR, "File is empty or exceeds limit\n");
		fclose(file);
		return -1;
	}
	buffer = (char*) malloc(length);
	if (buffer == NULL) {
		logger(LL_ERROR, "Out of memory\n");
		fclose(file);
		return -1;
	}
	bytes = fread(buffer, 1, length, file);
	fclose(file);
	
	if (bytes != length) {
		logger(LL_ERROR, "Unable to read entire file\n");
		free(buffer);
		return -1;
	}
	
	*size = length;
	*data = buffer;
	return 0;
}

void print_module_hash(const char* name, const uint8_t* buf, const size_t length)
{
	unsigned char tsha384[SHA384_DIGEST_LENGTH];
	memset(tsha384, 0, SHA384_DIGEST_LENGTH);
	sha384_context sha384ctx;
	sha384_init(&sha384ctx);
	sha384_update(&sha384ctx, buf, length);
	sha384_final(&sha384ctx, tsha384);
	
	printf("%s hash: ", name);
	for (int i = 0; i < SHA384_DIGEST_LENGTH; i++) {
		printf("%02x", tsha384[i]);
	}
	printf("\n");
}

uint32_t read_u32_le(const uint8_t *p)
{
	return (
			((uint32_t)p[0]      ) |
			((uint32_t)p[1] <<  8) |
			((uint32_t)p[2] << 16) |
			((uint32_t)p[3] << 24)
			);
}

uint64_t read_u64_le(const unsigned char *p)
{
	return (uint64_t)p[0] |
	((uint64_t)p[1] << 8) |
	((uint64_t)p[2] << 16) |
	((uint64_t)p[3] << 24) |
	((uint64_t)p[4] << 32) |
	((uint64_t)p[5] << 40) |
	((uint64_t)p[6] << 48) |
	((uint64_t)p[7] << 56);
}

void write_u32_le(uint8_t *buf, uint32_t value)
{
	buf[0] = (uint8_t)(value & 0xFFu);
	buf[1] = (uint8_t)((value >> 8) & 0xFFu);
	buf[2] = (uint8_t)((value >> 16) & 0xFFu);
	buf[3] = (uint8_t)((value >> 24) & 0xFFu);
}

void write_u64_le(uint8_t *buf, uint64_t value)
{
	buf[0] = (uint8_t)(value & 0xFFu);
	buf[1] = (uint8_t)((value >> 8) & 0xFFu);
	buf[2] = (uint8_t)((value >> 16) & 0xFFu);
	buf[3] = (uint8_t)((value >> 24) & 0xFFu);
	buf[4] = (uint8_t)((value >> 32) & 0xFFu);
	buf[5] = (uint8_t)((value >> 40) & 0xFFu);
	buf[6] = (uint8_t)((value >> 48) & 0xFFu);
	buf[7] = (uint8_t)((value >> 56) & 0xFFu);
}

// pongoOS
int hexparse(uint8_t *buf, char *s, size_t len)
{
	for(size_t i = 0; i < len; ++i)
	{
		char c = s[2*i],
		d = s[2*i+1];
		if(!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) ||
		   !((d >= '0' && d <= '9') || (d >= 'a' && d <= 'f') || (d >= 'A' && d <= 'F')))
		{
			return -1;
		}
		buf[i] = ((uint8_t)(c >= '0' && c <= '9' ? c - '0' : (c >= 'a' && c <= 'f' ? c - 'a' : c - 'A') + 10) << 4) |
		(uint8_t)(d >= '0' && d <= '9' ? d - '0' : (d >= 'a' && d <= 'f' ? d - 'a' : d - 'A') + 10);
	}
	return 0;
}

// sep_racer
bool is_bsep(sep_block_t* bsep)
{
	if (!bsep) {
		return false;
	}
	if (bsep->magic != BSEP_MAGIC) {
		return false;
	}
	return true;
}

bool bsep_validate(sep_block_t* bsep)
{
	if (!bsep) {
		return false;
	}
	if (is_bsep(bsep) == false) {
		return false;
	}
	switch (bsep->block_version) {
		case BSEP_VERSION_1:
			return true;
		default: // undefined
			break;
	}
	return false;
}

bool get_bsep_bversion(sep_block_t* bsep, uint32_t* rv)
{
	if (!bsep) {
		return false;
	}
	if (is_bsep(bsep) == false) {
		return false;
	}
	if (bsep_validate(bsep) == false) {
		return false;
	}
	if (rv) {
		*rv = bsep->block_version;
	}
	return true;
}

bool get_bsep_type(sep_block_t* bsep, uint32_t* rv)
{
	if (!bsep) {
		return false;
	}
	uint32_t bsep_bversion = 0;
	if (get_bsep_bversion(bsep, &bsep_bversion) == false) {
		return false;
	}
	if (bsep_bversion != BSEP_VERSION_1) {
		return false; // unknown version
	}
	if (bsep->type != BSEP_TYPE_SHC && bsep->type != BSEP_TYPE_PTE) {
		return false; // unknown type
	}
	if (rv) {
		*rv = bsep->type;
	}
	return true;
}

uint64_t convert_build_to_ios_vflag(int build_major)
{
	switch (build_major) {
		case 11:
			return IOS_VERSION_FLAG_7;
		case 12:
			return IOS_VERSION_FLAG_8;
		case 13:
			return IOS_VERSION_FLAG_9;
		case 14:
			return IOS_VERSION_FLAG_10;
		case 15:
			return IOS_VERSION_FLAG_11;
		case 16:
			return IOS_VERSION_FLAG_12;
		case 17:
			return IOS_VERSION_FLAG_13;
		case 18:
			return IOS_VERSION_FLAG_14;
		case 19:
			return IOS_VERSION_FLAG_15;
		case 20:
			return IOS_VERSION_FLAG_16;
		case 21:
			return IOS_VERSION_FLAG_17;
		case 22:
			return IOS_VERSION_FLAG_18;
		case 23:
			return IOS_VERSION_FLAG_26;
		default:
			return 0;
	}
}

int is_tvos_with_cpid_bdid(uint16_t cpid, uint8_t bdid)
{
	switch (cpid) {
		case 0x7000:
		{
			if (bdid == 0x34) { // AppleTV HD
				return 1;
			}
			else if (
					 bdid == 0x06 || // iPhone 6
					 bdid == 0x04 || // iPhone 6 Plus
					 bdid == 0x10 || // iPod touch 6G
					 bdid == 0x08 || // iPad mini 4
					 bdid == 0x0A    // iPad mini 4
					 )
			{
				return 0;
			}
			break;
		}
		case 0x7001:
		case 0x8000:
		case 0x8001:
		case 0x8003:
		case 0x8010:
			return 0;
		case 0x8011:
		{
			if (bdid == 0x02) { // AppleTV 4K
				return 1;
			}
			else if (
					 bdid == 0x0C || // iPad Pro 12.9-inch (2nd generation)
					 bdid == 0x0E || // iPad Pro 12.9-inch (2nd generation)
					 bdid == 0x04 || // iPad Pro 10.5-inch
					 bdid == 0x06    // iPad Pro 10.5-inch
					 )
			{
				return 0;
			}
			break;
		}
		default:
			break;
	}
	return -1;
}

uint64_t convert_cpid_bdid_to_plat_vflag(uint16_t cpid, uint8_t bdid)
{
	int is_tvos = is_tvos_with_cpid_bdid(cpid, bdid);
	switch (cpid) {
		case 0x7000:
		{
			if (is_tvos == 1) {
				return PLATFORM_FLAG_ENV_TVOS | PLATFORM_FLAG_CPID_7000;
			}
			else if (is_tvos == 0) {
				return PLATFORM_FLAG_ENV_IOS | PLATFORM_FLAG_CPID_7000;
			}
			break;
		}
		case 0x7001:
			return PLATFORM_FLAG_ENV_IOS | PLATFORM_FLAG_CPID_7001;
		case 0x8000:
			return PLATFORM_FLAG_ENV_IOS | PLATFORM_FLAG_CPID_8000;
		case 0x8001:
			return PLATFORM_FLAG_ENV_IOS | PLATFORM_FLAG_CPID_8001;
		case 0x8003:
			return PLATFORM_FLAG_ENV_IOS | PLATFORM_FLAG_CPID_8003;
		case 0x8010:
			return PLATFORM_FLAG_ENV_IOS | PLATFORM_FLAG_CPID_8010;
		case 0x8011:
		{
			if (is_tvos == 1) {
				return PLATFORM_FLAG_ENV_TVOS | PLATFORM_FLAG_CPID_8011;
			}
			else if (is_tvos == 0) {
				return PLATFORM_FLAG_ENV_IOS | PLATFORM_FLAG_CPID_8011;
			}
			break;
		}
		default:
			break;
	}
	return 0;
}

int load_rdsk_flag(const uint8_t* bin, size_t bin_len, uint64_t flag, const char* name, uint64_t* out_flag)
{
	uint8_t* buf = NULL;
	if (bin_len < sizeof(rdsk_bin_t)) {
		logger(LL_ERROR, "%s module too small\n", name);
		return -1;
	}
	int res = posix_memalign((void**)&buf, 8, bin_len);
	if (res != 0) {
		logger(LL_ERROR, "Alloc failed: %s\n", name);
		return -2;
	}
	memset(buf, 0, bin_len);
	memcpy(buf, bin, bin_len);
	int success = 0;
	if (
		(read_u32_le((uint8_t*)buf + offsetof(rdsk_bin_t, magic)) == 0xca1337feu) &&
		(read_u64_le((uint8_t*)buf + offsetof(rdsk_bin_t, type)) == (0x0000cafebabe9990uLL | (flag << 48)))
		)
	{
		if (out_flag) {
			*out_flag = read_u64_le((uint8_t*)buf + offsetof(rdsk_bin_t, tag));
		}
		success = 1;
	}
	free(buf);
	if (!success) {
		logger(LL_ERROR, "Invalid %s module\n", name);
		return -3;
	}
	return 0;
}

int load_module_flag(const uint8_t* bin, size_t bin_len, uint64_t magic, const char* name, uint64_t* out_flag)
{
	if (bin_len < (0x40 + sizeof(uint64_t))) {
		logger(LL_ERROR, "%s module too small\n", name);
		return -1;
	}
	
	uint8_t* buf = NULL;
	int res = posix_memalign((void**)&buf, 8, bin_len);
	if (res != 0) {
		logger(LL_ERROR, "Alloc failed for %s\n", name);
		return -2;
	}
	
	memcpy(buf, bin, bin_len);
	uint8_t* cur = buf;
	int found = 0;
	const uint8_t* end = buf + bin_len - (0x40 + sizeof(uint64_t));
	
	while (cur <= end) {
		if ((read_u64_le(cur + 0x00) == (magic | 0x0000cafebabe0000uLL)) &&
			(read_u64_le(cur + 0x08) == (magic | 0x0000cafebabe0001uLL)) &&
			(read_u64_le(cur + 0x10) == (magic | 0x0000cafebabe0002uLL)) &&
			(read_u64_le(cur + 0x18) == (magic | 0x0000cafebabe0003uLL)) &&
			(read_u64_le(cur + 0x28) == (magic | 0x0000cafebabe000cuLL)) &&
			(read_u64_le(cur + 0x30) == (magic | 0x0000cafebabe000duLL)) &&
			(read_u64_le(cur + 0x38) == (magic | 0x0000cafebabe000euLL)) &&
			(read_u64_le(cur + 0x40) == (magic | 0x0000cafebabe000fuLL))
			)
		{
			if (out_flag) {
				*out_flag = read_u64_le(cur + 0x20);
			}
			found = 1;
			break;
		}
		cur += sizeof(uint64_t);
	}
	
	free(buf);
	
	if (!found) {
		logger(LL_ERROR, "Invalid %s module\n", name);
		return -3;
	}
	
	return 0;
}

int check_vflag(uint64_t flag, uint64_t mask)
{
	if ((flag & mask) == mask) {
		return 1;
	}
	return 0;
}

#pragma mark - idevicerestore
int build_identity_get_component_digest(plist_t build_identity, const char* component, uint8_t** buffer, size_t *len)
{
	plist_t manifest_node = plist_dict_get_item(build_identity, "Manifest");
	if (!manifest_node || plist_get_node_type(manifest_node) != PLIST_DICT) {
		logger(LL_ERROR, "Unable to find manifest node\n");
		return -1;
	}
	
	plist_t component_node = plist_dict_get_item(manifest_node, component);
	if (!component_node || plist_get_node_type(component_node) != PLIST_DICT) {
		logger(LL_ERROR, "Unable to find component node for %s\n", component);
		return -1;
	}
	
	plist_t digest_node = plist_dict_get_item(component_node, "Digest");
	if (!digest_node || plist_get_node_type(digest_node) != PLIST_DATA) {
		logger(LL_ERROR, "Unable to find digest node\n");
		return -1;
	}
	
	uint8_t* digest_data = NULL;
	size_t digest_data_len = 0;
	plist_get_data_val(digest_node, (char**)&digest_data, (uint64_t*)&digest_data_len);
	if (!digest_data) {
		logger(LL_ERROR, "Unable to find digest data\n");
		if (digest_data) free(digest_data);
		return -1;
	}
	uint8_t* _dgst_hash = (uint8_t*)digest_data;
	fprintf(stderr, "%s digest: ", component);
	for (int i = 0; i < digest_data_len; i++) {
		fprintf(stderr, "%02x", _dgst_hash[i]);
	}
	fprintf(stderr, "\n");
	
	if (buffer && len) {
		*buffer = digest_data;
		*len = digest_data_len;
	}
	else {
		if (digest_data) free(digest_data);
	}
	digest_data = NULL;
	digest_data_len = 0;
	return 0;
}

static int validate_fdr_firmware_component_hash(struct idevicerestore_client_t* client, plist_t build_identity, const char* component)
{
	int rv = -1;
	plist_t tss_data = NULL;
	char* im4m_data = NULL;
	uint64_t im4m_data_len = 0;
	uint8_t* hash = NULL;
	size_t hash_len = 0;
	
	static uint8_t customer_dgst[] = {
		0x53, 0x40, 0xb6, 0xa0, 0x59, 0xbd, 0xb7, 0x32,
		0xe7, 0x15, 0xe7, 0xbb, 0x1b, 0x29, 0x2e, 0xdc,
		0xd4, 0x5c, 0x2a, 0x8d, 0x1d, 0x07, 0xe6, 0x03,
		0x9d, 0x3f, 0x33, 0x8d, 0x7c, 0x44, 0x28, 0xab
	};
	static uint8_t factory_dgst[] = {
		0x55, 0x67, 0xc6, 0xbe, 0x8a, 0xbd, 0xca, 0xff,
		0x00, 0x8d, 0x00, 0x1e, 0xd5, 0x95, 0x51, 0x49,
		0xc4, 0x1c, 0x3d, 0xfc, 0x17, 0x56, 0xaf, 0x01,
		0x14, 0xe3, 0x84, 0xc7, 0xcd, 0xc1, 0x41, 0x1f
	};
	
	if (!client || !build_identity || !component) {
		rv = -1;
		goto end;
	}
	
	if (!build_identity_has_component(build_identity, component)) {
		rv = 1; // not used
		goto end;
	}
	
	tss_data = plist_copy(client->local_shsh);
	if (!tss_data) {
		logger(LL_ERROR, "local TSS data not found\n");
		rv = -2;
		goto end;
	}
	plist_t apimg4ticket = plist_dict_get_item(tss_data, "ApImg4Ticket");
	if (!apimg4ticket) {
		logger(LL_ERROR, "no ApImg4Ticket dict\n");
		rv = -3;
		goto end;
	}
	plist_get_data_val(apimg4ticket, &im4m_data, &im4m_data_len);
	if (!im4m_data) {
		logger(LL_ERROR, "no img4 manifest\n");
		rv = -4;
		goto end;
	}

	int result = get_img4_digest_from_manifest(client, build_identity, component, (const uint8_t *)im4m_data, im4m_data_len, &hash, &hash_len);
	if (result == 2) {
		rv = 2; // not in im4p
		goto end;
	}
	if (result < 0) {
		rv = result;
		goto end;
	}

	if (hash_len != 0x20) {
		rv = 4; // unknown hash length
		goto end;
	}

	if (!memcmp(hash, &customer_dgst, 0x20)) {
		rv = 0; // customer DGST
		goto end;
	}

	if (!memcmp(hash, &factory_dgst, 0x20)) {
		rv = 3; // factory DGST
		goto end;
	}

	rv = 4; // unknown DGST

end:
	if (hash) free(hash);
	if (tss_data) free(tss_data);
	if (im4m_data) free(im4m_data);
	return rv;
}

static int validate_memory_firmware_component_hash(struct idevicerestore_client_t* client, plist_t build_identity, const char* component, unsigned char* compdata, unsigned int compdata_len, plist_t tss, bool verify_manifest, bool verify_payload, uint32_t* result)
{
	int rv = -1;
	unsigned char* im4p_data = NULL;
	unsigned int im4p_data_len = 0;
	plist_t tss_data = NULL;
	char* im4m_data = NULL;
	uint64_t im4m_data_len = 0;
	
	if (!client || !build_identity || !component) {
		rv = -1;
		goto end;
	}
	
	if (!build_identity_has_component(build_identity, component)) {
		rv = 1;
		goto end;
	}
	
	if (verify_payload) {
		if (!compdata || !!compdata_len) {
			rv = -2;
			goto end;
		}
	}
	
	if (verify_manifest) {
		if (!tss) {
			rv = -3;
			goto end;
		}
	}
	
	logger(LL_DEBUG, "---- checking %s hash ----\n", component);
	
	if (verify_payload) {
		im4p_data_len = compdata_len;
		im4p_data = malloc(im4p_data_len);
		if (!im4p_data) {
			logger(LL_ERROR, "malloc failed\n");
			rv = -4;
			goto end;
		}
		memcpy(im4p_data, compdata, im4p_data_len);
		img4_override_payload_tag(component, im4p_data);
	}
	
	
	if (verify_manifest) {
		tss_data = plist_copy(tss);
		if (!tss_data) {
			logger(LL_ERROR, "local TSS data not found\n");
			rv = -5;
			goto end;
		}
		plist_t apimg4ticket = plist_dict_get_item(tss_data, "ApImg4Ticket");
		if (!apimg4ticket) {
			logger(LL_ERROR, "no ApImg4Ticket dict\n");
			rv = -6;
			goto end;
		}
		plist_get_data_val(apimg4ticket, &im4m_data, &im4m_data_len);
		if (!im4m_data) {
			logger(LL_ERROR, "no img4 manifest\n");
			rv = -7;
			goto end;
		}
	}
	
	int res = validate_img4_digest(client, build_identity, component, im4p_data, im4p_data_len, (const uint8_t *)im4m_data, im4m_data_len, verify_manifest, verify_payload, result);
	
	if (res < 0) {
		logger(LL_ERROR, "hash validation failed\n");
	}
	
	rv = res;
	
end:
	if (im4p_data) free(im4p_data);
	if (im4m_data) free(im4m_data);
	if (tss_data) free(tss_data);
	return rv;
}

static int validate_ipsw_firmware_component_hash(struct idevicerestore_client_t* client, plist_t build_identity, const char* component, bool verify_manifest, bool verify_payload, uint32_t* result)
{
	int rv = -1;
	char* path = NULL;
	unsigned char* im4p_data = NULL;
	size_t im4p_data_len = 0;
	plist_t tss_data = NULL;
	char* im4m_data = NULL;
	uint64_t im4m_data_len = 0;
	uint32_t _result = 0;
	
	if (!client || !build_identity || !component) {
		rv = -1;
		goto end;
	}
	
	if (!build_identity_has_component(build_identity, component)) {
		rv = 1;
		goto end;
	}
	
	logger(LL_DEBUG, "---- checking %s hash ----\n", component);
	
	if (verify_payload) {
		if (build_identity_get_component_path(build_identity, component, &path)) {
			logger(LL_ERROR, "Unable to find path: %s\n", component);
			rv = -2;
			goto end;
		}
		if (extract_component(client->ipsw, path, (void **)&im4p_data, &im4p_data_len) < 0) {
			logger(LL_ERROR, "Unable to extract component: %s\n", component);
			rv = -3;
			goto end;
		}
		img4_override_payload_tag(component, im4p_data);
	}
	
	if (verify_manifest) {
		tss_data = plist_copy(client->local_shsh);
		if (!tss_data) {
			logger(LL_ERROR, "local TSS data not found\n");
			rv = -4;
			goto end;
		}
		plist_t apimg4ticket = plist_dict_get_item(tss_data, "ApImg4Ticket");
		if (!apimg4ticket) {
			logger(LL_ERROR, "no ApImg4Ticket dict\n");
			rv = -5;
			goto end;
		}
		plist_get_data_val(apimg4ticket, &im4m_data, &im4m_data_len);
		if (!im4m_data) {
			logger(LL_ERROR, "no img4 manifest\n");
			rv = -6;
			goto end;
		}
	}
	
	int res = validate_img4_digest(client, build_identity, component,
								   im4p_data, im4p_data_len, (const uint8_t *)im4m_data, (size_t)im4m_data_len,
								   verify_manifest, verify_payload, result);
	
	if (res < 0) {
		logger(LL_ERROR, "hash validation failed\n");
	}
	
	rv = res;
	
end:
	if (path) free(path);
	if (im4p_data) free(im4p_data);
	if (im4m_data) free(im4m_data);
	if (tss_data) free(tss_data);
	return rv;
}

int check_firmware_components(struct idevicerestore_client_t* client, plist_t build_identity)
{
	if (client->flags & FLAG_TETHERED) {
		return 0;
	}
	
	// it is untethered, so requires full verification
#define IMG4_VALIDATE_NONE          (0)
#define IMG4_VALIDATE_MANIFEST      (1u << 0)
#define IMG4_VALIDATE_PAYLOAD       (1u << 1)
#define IMG4_MANIFEST_MUST_MATCHED  (1u << 2)
#define IMG4_PAYLOAD_MUST_MATCHED   (1u << 3)
	
#define IMG4_VALIDATE_ALL          (IMG4_VALIDATE_MANIFEST | IMG4_VALIDATE_PAYLOAD | IMG4_MANIFEST_MUST_MATCHED | IMG4_PAYLOAD_MUST_MATCHED)
#define IMG4_VALIDATE_RESTORE      (IMG4_VALIDATE_MANIFEST | IMG4_VALIDATE_PAYLOAD | IMG4_PAYLOAD_MUST_MATCHED)
	
	struct filename_component_map {
		uint32_t validate_flag;
		const char *compname;
	};
	struct filename_component_map fn_comp[] = {
		{ IMG4_VALIDATE_ALL,     "AOP" },
		{ IMG4_VALIDATE_ALL,     "AVE" },
		{ IMG4_VALIDATE_ALL,     "Ap,SystemVolumeCanonicalMetadata" },
		{ IMG4_VALIDATE_ALL,     "AppleLogo" },
		{ IMG4_VALIDATE_ALL,     "BatteryCharging0" },
		{ IMG4_VALIDATE_ALL,     "BatteryCharging1" },
		{ IMG4_VALIDATE_ALL,     "BatteryFull" },
		{ IMG4_VALIDATE_ALL,     "BatteryLow0" },
		{ IMG4_VALIDATE_ALL,     "BatteryLow1" },
		{ IMG4_VALIDATE_ALL,     "BatteryPlugin" },
		{ IMG4_VALIDATE_ALL,     "DeviceTree" },
		{ IMG4_VALIDATE_ALL,     "Homer" },
		{ IMG4_VALIDATE_ALL,     "KernelCache" },
		{ IMG4_VALIDATE_ALL,     "LLB" },
		{ IMG4_VALIDATE_ALL,     "Liquid" },
		{ IMG4_VALIDATE_ALL,     "Multitouch" },
		{ IMG4_VALIDATE_ALL,     "RecoveryMode" },
		{ IMG4_VALIDATE_RESTORE, "RestoreDeviceTree" },
		{ IMG4_VALIDATE_RESTORE, "RestoreKernelCache" },
		{ IMG4_VALIDATE_RESTORE, "RestoreLogo" },
		{ IMG4_VALIDATE_RESTORE, "RestoreRamDisk" },
		{ IMG4_VALIDATE_RESTORE, "RestoreSEP" },
		{ IMG4_VALIDATE_RESTORE, "RestoreTrustCache" },
		{ IMG4_VALIDATE_ALL,     "SEP" },
		{ IMG4_VALIDATE_ALL,     "StaticTrustCache" },
		{ IMG4_VALIDATE_ALL,     "SystemVolume" },
		{ IMG4_VALIDATE_RESTORE, "iBEC" },
		{ IMG4_VALIDATE_RESTORE, "iBSS" },
		{ IMG4_VALIDATE_ALL,     "iBoot" },
		{ IMG4_VALIDATE_NONE,     NULL }
	};
	
	int bypass_trustcache_check = 0;
	{
		// check Manifest hash
		uint8_t* im4m_data = NULL;
		uint64_t im4m_data_len = 0;
		uint8_t* hash = NULL;
		size_t hash_len = 0;
		plist_t tss_data = plist_copy(client->local_shsh);
		if (!tss_data) {
			logger(LL_ERROR, "local TSS data not found\n");
			return -1;
		}
		plist_t apimg4ticket = plist_dict_get_item(tss_data, "ApImg4Ticket");
		if (!apimg4ticket) {
			logger(LL_ERROR, "no ApImg4Ticket dict\n");
			plist_free(tss_data);
			return -1;
		}
		plist_get_data_val(apimg4ticket, (char**)&im4m_data, &im4m_data_len);
		if (!im4m_data) {
			logger(LL_ERROR, "no img4 manifest\n");
			plist_free(tss_data);
			return -1;
		}
		
		if (get_image4_manifest_hash(im4m_data, im4m_data_len, 'rdsk', &hash, &hash_len) == 0) {
			logger(LL_INFO, "Found RestoreRamdisk digest\n");
			fprintf(stderr, "DGST: ");
			int i;
			for (i = 0; i < hash_len; i++) {
				fprintf(stderr, "%02x", hash[i]);
			}
			fprintf(stderr, "\n");
			if (hash_len == 0x14) {
				uint8_t ota_rdsk_16A366[0x14] = {
					0x81, 0x4D, 0xEA, 0x13, 0xEE, 0x34, 0xB3, 0x44, 0x52, 0x78, 0x02, 0xAA, 0x66, 0x6E, 0x75, 0xEB, 0x18, 0x81, 0x7C, 0xBF
				};
				uint8_t ota_rdsk_16A404[0x14] = {
					0xE1, 0xAA, 0x8F, 0xA1, 0x35, 0x5C, 0x9E, 0x97, 0x76, 0x97, 0xC6, 0x10, 0xC7, 0xA7, 0x19, 0x7C, 0x3E, 0x5A, 0x93, 0xDE
				};
				if (memcmp(hash, ota_rdsk_16A366, 0x14) == 0 || memcmp(hash, ota_rdsk_16A404, 0x14) == 0) {
					logger(LL_INFO, "Found the weird image4 manifest\n");
					bypass_trustcache_check = 1;
				}
			}
			else if (hash_len == 0x30) {
				uint8_t ota_rdsk_16A366[0x30] = {
					0xEF, 0xC8, 0x07, 0x47, 0xB6, 0xF1, 0xC5, 0x1B, 0x6B, 0xC9, 0xB5, 0x00, 0x92, 0x14, 0xF6, 0x6F,
					0x6F, 0x6A, 0x4C, 0x58, 0x9E, 0xA9, 0x55, 0x62, 0x7A, 0x0F, 0x39, 0x97, 0x11, 0x75, 0x21, 0xD2,
					0xA3, 0xE7, 0xA3, 0x79, 0x54, 0xDD, 0xC1, 0x4C, 0x85, 0xF0, 0x44, 0x6A, 0xFC, 0x4D, 0x61, 0x61
				};
				uint8_t ota_rdsk_16A404[0x30] = {
					0x97, 0xE9, 0x91, 0x48, 0x90, 0x4E, 0x57, 0xC5, 0xF7, 0x65, 0xA8, 0x0A, 0x0C, 0x00, 0x9A, 0xE5,
					0xAC, 0xD1, 0x2E, 0x6C, 0x14, 0x89, 0x9C, 0xE6, 0xEF, 0x88, 0x0F, 0x14, 0xFD, 0x5C, 0x86, 0x0D,
					0x23, 0x70, 0x38, 0x93, 0x5F, 0x8E, 0x6D, 0x78, 0x5E, 0x80, 0x5D, 0x47, 0xDD, 0xBF, 0xD2, 0xC2
				};
				if (memcmp(hash, ota_rdsk_16A366, 0x30) == 0 || memcmp(hash, ota_rdsk_16A404, 0x30) == 0) {
					logger(LL_INFO, "Found the weird image4 manifest\n");
					bypass_trustcache_check = 1;
				}
			}
		}
		
		if (tss_data) plist_free(tss_data);
		if (im4m_data) free(im4m_data);
		if (hash) free(hash);
	}
	uint32_t result = 0;
	int res = 0;
	int i = 0;
	while (fn_comp[i].compname) {
		result = 0;
		if (bypass_trustcache_check) {
			if (!strcmp(fn_comp[i].compname, "RestoreTrustCache")) {
				goto skip_validate;
			}
			if (!strcmp(fn_comp[i].compname, "StaticTrustCache")) {
				fn_comp[i].validate_flag = IMG4_VALIDATE_PAYLOAD | IMG4_PAYLOAD_MUST_MATCHED;
			}
		}
		res = validate_ipsw_firmware_component_hash(client, build_identity,
													fn_comp[i].compname,
													(fn_comp[i].validate_flag & IMG4_VALIDATE_MANIFEST) ? 1 : 0,
													(fn_comp[i].validate_flag & IMG4_VALIDATE_PAYLOAD) ? 1 : 0,
													&result);
		
		logger(LL_DEBUG, "image validation result: %d:%08x [comp: %s, flag: %08x]\n",
			  res, result,
			  fn_comp[i].compname,
			  fn_comp[i].validate_flag);
		
		switch (res) {
			case 0: // valid
				if (fn_comp[i].validate_flag & IMG4_MANIFEST_MUST_MATCHED) {
					if (!(result & IMG4_DIGEST_MATCHED_MANIFEST)) {
						logger(LL_ERROR, "Failed to image4 manifest check [comp: %s, res: %08x]\n", fn_comp[i].compname, result);
						return -1;
					}
				}
				if (fn_comp[i].validate_flag & IMG4_PAYLOAD_MUST_MATCHED) {
					if (!(result & IMG4_DIGEST_MATCHED_PAYLOAD)) {
						logger(LL_ERROR, "Failed to image4 payload check [comp: %s, res: %08x]\n", fn_comp[i].compname, result);
						return -1;
					}
				}
				break;
				
			case 1: // not used
				break;
				
			case 2: // not in im4p
				if (fn_comp[i].validate_flag & IMG4_MANIFEST_MUST_MATCHED) {
					logger(LL_ERROR, "image4 manifest check is required, but digest not found from manifest [comp: %s]\n", fn_comp[i].compname);
					return -1;
				}
				break;
				
			default:
				return -1;
		}
		
	skip_validate:
		i++;
	}
	
	// check OS digest
	if (client->build_major >= 14) { // iOS 9 or lower version does not have OS digest
		result = 0;
		res = validate_ipsw_firmware_component_hash(client, build_identity, "OS", 1, 0, &result);
		logger(LL_DEBUG, "image validation result: %d:%08x [comp: %s, manifest: %d:%d, payload: %d:%d]\n", res, result, "OS", 1, 1, 0, 0);
		
		switch (res) {
			case 0: // valid
				if (!(result & IMG4_DIGEST_MATCHED_MANIFEST))  {
					logger(LL_ERROR, "Failed to image4 manifest check [comp: %s, res: %08x]\n", "OS", result);
					return -1;
				}
				break;
				
			case 1: // not used
				break;
				
			case 2: // TODO: no rosi digest found in manifest
				if (client->build_major == 14) {
					logger(LL_INFO, "WARNING: no rosi digest found in manifest\n");
					client->need_asr_patch = 1;
					// modlue check
					if (is_arm64_soc(client->cpid)) {
						int is_tvos = is_tvos_with_cpid_bdid(client->cpid, client->bdid);
						uint64_t vflag = convert_build_to_ios_vflag(client->build_major);
						if (0 == check_vflag(client->kpf_flag, vflag)) {
							logger(LL_ERROR, "Found unsupported module (name: %s)\n", "kpf");
							return -1;
						}
						if (is_tvos == 0) { // iPhoneOS
							if (0 == check_vflag(client->union_iphoneos_flag, vflag)) {
								logger(LL_ERROR, "Found unsupported module (name: %s)\n", "union.dmg[iPhoneOS]");
								return -1;
							}
						}
						if (is_tvos == 1) { // tvOS
							if (0 == check_vflag(client->union_tvos_flag, vflag)) {
								logger(LL_ERROR, "Found unsupported module (name: %s)\n", "union.dmg[tvOS]");
								return -1;
							}
						}
					}
					break;
				}
				return -1;
				
			default:
				return -1;
		}
	}

	// check FDR digest
	struct fdr_component_map {
		bool manifest;
		const char *compname;
	};
	struct fdr_component_map fdr_comp[] = {
		{ 1, "ftap" },
		{ 1, "ftsp" },
		{ 1, "rfta" },
		{ 1, "rfts" },
		{ 0, NULL, }
	};
	
	i = 0;
	uint32_t has_weird_hash = 0;
	while (fdr_comp[i].compname) {
		res = validate_fdr_firmware_component_hash(client, build_identity, fdr_comp[i].compname);
		logger(LL_DEBUG, "FDR validation result: %d [comp: %s]\n", res, fn_comp[i].compname);
		
		switch (res) {
			case 0: // customer
				logger(LL_INFO, "Found customer %s digest in image4 manifest\n", fdr_comp[i].compname);
				break;
				
			case 1: // not used
				break;
				
			case 2: // TODO: Some old shsh1 does not accidentally save these
				logger(LL_ERROR, "%s digest not found\n", fdr_comp[i].compname);
				return -1;
				
			case 3: // TODO: This appears to be a chain used in the factory
				logger(LL_INFO, "Found non-customer %s digest in image4 manifest\n", fdr_comp[i].compname);
				has_weird_hash |= 1 << 0;
				break;
				
			case 4: // TODO: Unknown DGST
				logger(LL_INFO, "WARNING: Found unknown %s digest\n", fdr_comp[i].compname);
				has_weird_hash |= 1 << 1;
				break;
				
			default:
				return -1;
		}
		i++;
	}
	
	if (has_weird_hash) {
		const char* errstr = NULL;
		if (has_weird_hash & (1 << 1)) {
			errstr = "unknown FDR hashes.     ";
		}
		else {
			errstr = "non-customer FDR hashes.";
		}
		if (client->flags & FLAG_INTERACTIVE) {
			char input[64];
			printf("######################## [ WARNING ] ########################\n"
				   "# Found %s                            #\n"
				   "# This means that the restore may fail causing FDR error.   #\n"
				   "# If you want to continue, please type YES and press ENTER. #\n"
				   "#############################################################\n", errstr);
			while (1) {
				printf("> ");
				fflush(stdout);
				fflush(stdin);
				input[0] = '\0';
				get_user_input(input, 63, 0);
				if (client->flags & FLAG_QUIT) {
					return -1;
				}
				if (*input != '\0' && !strcmp(input, "YES")) {
					break;
				} else {
					printf("Invalid input. Please type YES or hit CTRL+C to abort.\n");
					continue;
				}
			}
		}
	}
	return 0;
}

int force_get_tss_response(struct idevicerestore_client_t* client, plist_t build_identity, plist_t* tss)
{
	plist_t request = NULL;
	plist_t response = NULL;
	*tss = NULL;
	
	logger(LL_INFO, "Trying to fetch new SHSH blob\n");
	
	/* populate parameters */
	plist_t parameters = plist_new_dict();
	plist_dict_merge(&parameters, client->parameters);
	
	plist_dict_set_item(parameters, "ApECID", plist_new_uint(client->ecid));
	if (client->nonce) {
		plist_dict_set_item(parameters, "ApNonce", plist_new_data((const char*)client->nonce, client->nonce_size));
	}
	
	if (!plist_dict_get_item(parameters, "SepNonce")) {
		unsigned char* sep_nonce = NULL;
		unsigned int sep_nonce_size = 0;
		get_sep_nonce(client, &sep_nonce, &sep_nonce_size);
		if (sep_nonce) {
			plist_dict_set_item(parameters, "ApSepNonce", plist_new_data((const char*)sep_nonce, sep_nonce_size));
			free(sep_nonce);
		}
	}
	
	plist_dict_set_item(parameters, "ApProductionMode", plist_new_bool(1));
	if (client->image4supported) {
		plist_dict_set_item(parameters, "ApSecurityMode", plist_new_bool(1));
		plist_dict_set_item(parameters, "ApSupportsImg4", plist_new_bool(1));
	}
	else {
		plist_dict_set_item(parameters, "ApSupportsImg4", plist_new_bool(0));
	}
	
	tss_parameters_add_from_manifest(parameters, build_identity, true);
	
	/* create basic request */
	request = tss_request_new(NULL);
	if (request == NULL) {
		logger(LL_ERROR, "Unable to create TSS request\n");
		plist_free(parameters);
		return -1;
	}
	
	/* add common tags from manifest */
	if (tss_request_add_common_tags(request, parameters, NULL) < 0) {
		logger(LL_ERROR, "Unable to add common tags to TSS request\n");
		plist_free(request);
		plist_free(parameters);
		return -1;
	}
	
	/* add tags from manifest */
	if (tss_request_add_ap_tags(request, parameters, NULL) < 0) {
		logger(LL_ERROR, "Unable to add common tags to TSS request\n");
		plist_free(request);
		plist_free(parameters);
		return -1;
	}
	
	if (client->image4supported) {
		/* add personalized parameters */
		if (tss_request_add_ap_img4_tags(request, parameters) < 0) {
			logger(LL_ERROR, "Unable to add img4 tags to TSS request\n");
			plist_free(request);
			plist_free(parameters);
			return -1;
		}
	}
	else {
		/* add personalized parameters */
		if (tss_request_add_ap_img3_tags(request, parameters) < 0) {
			logger(LL_ERROR, "Unable to add img3 tags to TSS request\n");
			plist_free(request);
			plist_free(parameters);
			return -1;
		}
	}
	
	if (client->mode == MODE_NORMAL) {
		/* normal mode; request baseband ticket aswell */
		plist_t pinfo = NULL;
		normal_get_firmware_preflight_info(client, &pinfo);
		if (pinfo) {
			plist_dict_copy_data(parameters, pinfo, "BbNonce", "Nonce");
			plist_dict_copy_uint(parameters, pinfo, "BbChipID", "ChipID");
			plist_dict_copy_uint(parameters, pinfo, "BbGoldCertId", "CertID");
			plist_dict_copy_data(parameters, pinfo, "BbSNUM", "ChipSerialNo");
			/* add baseband parameters */
			tss_request_add_baseband_tags(request, parameters, NULL);
			
			plist_dict_copy_uint(parameters, pinfo, "eUICC,ChipID", "EUICCChipID");
			if (plist_dict_get_uint(parameters, "eUICC,ChipID") >= 5) {
				plist_dict_copy_data(parameters, pinfo, "eUICC,EID", "EUICCCSN");
				plist_dict_copy_data(parameters, pinfo, "eUICC,RootKeyIdentifier", "EUICCCertIdentifier");
				plist_dict_copy_data(parameters, pinfo, "EUICCGoldNonce", NULL);
				plist_dict_copy_data(parameters, pinfo, "EUICCMainNonce", NULL);
				/* add vinyl parameters */
				tss_request_add_vinyl_tags(request, parameters, NULL);
			}
		}
		client->firmware_preflight_info = pinfo;
		pinfo = NULL;
		
		normal_get_preflight_info(client, &pinfo);
		client->preflight_info = pinfo;
	}
	
	response = tss_request_send(request, client->tss_url);
	if (response == NULL) {
		logger(LL_ERROR, "Unable to send TSS request\n");
		plist_free(request);
		plist_free(parameters);
		return -1;
	}
	
	logger(LL_INFO, "Received SHSH blobs\n");
	
	plist_free(request);
	plist_free(parameters);
	
	*tss = response;
	
	return 0;
}

int is_armv7s_soc(uint16_t cpid)
{
	switch (cpid) {
		case 0x8950:
		case 0x8955:
			return 1;
		default:
			break;
	}
	return 0;
}

int is_arm64_soc(uint16_t cpid)
{
	switch (cpid) {
		case 0x8960:
		case 0x7000:
		case 0x7001:
		case 0x8000:
		case 0x8001:
		case 0x8003:
		case 0x8010:
		case 0x8011:
		case 0x8012:
		case 0x8015:
			return 1;
		default:
			break;
	}
	return 0;
}

int is_a8_variant_soc(uint16_t cpid)
{
	switch (cpid) {
		case 0x7000:
		case 0x7001:
			return 1;
		default:
			break;
	}
	return 0;
}

int is_a9_variant_soc(uint16_t cpid)
{
	switch (cpid) {
		case 0x8000:
		case 0x8001:
		case 0x8003:
			return 1;
		default:
			break;
	}
	return 0;
}

int is_a10_variant_soc(uint16_t cpid)
{
	switch (cpid) {
		case 0x8010:
		case 0x8011:
			return 1;
		default:
			break;
	}
	return 0;
}

int have_arm64_second_stage_iboot(uint16_t cpid)
{
	switch (cpid) {
		case 0x8960:
		case 0x7000:
		case 0x7001:
		case 0x8000:
		case 0x8001:
		case 0x8003:
			return 1;
		default:
			break;
	}
	return 0;
}

int have_arm64_single_stage_iboot(uint16_t cpid)
{
	switch (cpid) {
		case 0x8010:
		case 0x8011:
		case 0x8012:
		case 0x8015:
			return 1;
		default:
			break;
	}
	return 0;
}

#pragma mark - img4
#define _ASN1_PRIVATE 0xc0
#define _ASN1_PRIMITIVE_TAG 0x1f
#define _ASN1_CONSTRUCTED 0x20
#define _ASN1_SEQUENCE 0x10
#define _ASN1_SET 0x11
#define _ASN1_CONTEXT_SPECIFIC 0x80
#define _ASN1_IA5_STRING 0x16
#define _ASN1_OCTET_STRING 0x04
#define _ASN1_INTEGER 0x02
#define _ASN1_BOOLEAN 0x01
void img4_override_payload_tag(const char* component_name, const unsigned char* component_data)
{
	const void *tag = asn1_find_element(1, _ASN1_IA5_STRING, component_data);
	if (tag) {
		logger(LL_DEBUG, "Tag found\n");
		if (!strcmp(component_name, "RestoreKernelCache")) {
			memcpy((void*)tag, "rkrn", 4);
		}
		if (!strcmp(component_name, "RestoreDeviceTree")) {
			memcpy((void*)tag, "rdtr", 4);
		}
		if (!strcmp(component_name, "RestoreSEP")) {
			memcpy((void*)tag, "rsep", 4);
		}
		if (!strcmp(component_name, "RestoreLogo")) {
			memcpy((void*)tag, "rlgo", 4);
		}
		if (!strcmp(component_name, "RestoreTrustCache")) {
			memcpy((void*)tag, "rtsc", 4);
		}
	}
}

static int get_img4_payload_tag(const char* component_name, const unsigned char* component_data, uint32_t* rv)
{
	const uint32_t *tag = (const uint32_t *)asn1_find_element(1, _ASN1_IA5_STRING, component_data);
	if (tag) {
		logger(LL_DEBUG, "Tag found\n");
		*rv = ntohl(tag[0]);
		return 0;
	}
	return -1;
}

static int get_img4_type_tag(const char* component_name, uint32_t* rv)
{
	uint32_t tag = 0;
	const char* _tag = _img4_get_component_tag(component_name);
	if (_tag == NULL) {
		return -1;
	}
	
	memcpy((void*)&tag, _tag, 4);
	if (!strcmp(component_name, "OS")) {
		memcpy((void*)&tag, "rosi", 4);
	}
	*rv = ntohl(tag);
	return 0;
}

#pragma mark - img4lib
// original by xerub
#define E000000000000000 (ASN1_CONSTRUCTED | ASN1_PRIVATE)
#define RESERVE_DIGEST_SPACE 20

typedef struct {
	DERItem item;
	DERTag tag;
} DERMonster;

typedef struct {
	DERItem magic;      // "IM4M"
	DERItem version;    // 0
	DERItem theset;     // MANB + MANP
	DERItem sig_blob;   // RSA
	DERItem chain_blob; // cert chain
	DERItem img4_blob;
	DERByte full_digest[RESERVE_DIGEST_SPACE];
	DERByte theset_digest[RESERVE_DIGEST_SPACE];
} TheImg4Manifest;

const DERItemSpec DERImg4ManifestItemSpecs[5] = {
	{ 0 * sizeof(DERItem), ASN1_IA5_STRING,      0 },                    // "IM4M"
	{ 1 * sizeof(DERItem), ASN1_INTEGER,         0 },                    // 0
	{ 2 * sizeof(DERItem), ASN1_CONSTR_SET,      DER_DEC_SAVE_DER },     // SET(things)
	{ 3 * sizeof(DERItem), ASN1_OCTET_STRING,    0 },                    // RSA
	{ 4 * sizeof(DERItem), ASN1_CONSTR_SEQUENCE, 0 }                     // chain
};

static int DERImg4DecodeFindInSequence(unsigned char *a1, unsigned char *a2, DERTag tag, DERItem *a5)
{
	DERDecodedInfo currDecoded;
	DERSequence derSeq;
	
	derSeq.nextItem = a1;
	derSeq.end = a2;
	
	do {
		int rv = DERDecodeSeqNext(&derSeq, &currDecoded);
		if (rv) {
			return rv;
		}
	} while (currDecoded.tag != tag);
	
	*a5 = currDecoded.content;
	return 0;
}

static int DERImg4DecodeContentFindItemWithTag(const DERItem *a1, DERTag tag, DERItem *a4)
{
	int rv;
	DERSequence derSeq;
	
	rv = DERDecodeSeqContentInit(a1, &derSeq);
	if (rv) {
		return rv;
	}
	return DERImg4DecodeFindInSequence(derSeq.nextItem, derSeq.end, tag, a4);
}

static int DERImg4DecodeTagCompare(const DERItem *a1, uint32_t nameTag)
{
	uint32_t var_14;
	
	if (a1->length < 4) {
		return -1;
	}
	if (a1->length > 4) {
		return 1;
	}
	
	if (DERParseInteger(a1, &var_14)) {
		return -2;
	}
	
	if (var_14 < nameTag) {
		return -1;
	}
	if (var_14 > nameTag) {
		return 1;
	}
	return 0;
}

static int DERImg4DecodeManifest(const DERItem *a1, TheImg4Manifest *a2)
{
	int rv;
	uint32_t var_14;
	
	if (a1 == NULL || a2 == NULL) {
		return DR_ParamErr;
	}
	if (a1->data == NULL || a1->length == 0) {
		return 0;
	}
	
	rv = DERParseSequence(a1, 5, DERImg4ManifestItemSpecs, a2, 0);
	if (rv) {
		return rv;
	}
	
	if (DERImg4DecodeTagCompare(&a2->magic, 'IM4M')) {
		return DR_UnexpectedTag;
	}
	
	rv = DERParseInteger(&a2->version, &var_14);
	if (rv) {
		return rv;
	}
	
	if (var_14) {
		return DR_UnexpectedTag;
	}
	return 0;
}

static int DERImg4DecodeProperty(const DERItem *a1, DERTag etag, DERMonster *a4)
{
	int rv;
	uint32_t var_6C;
	DERTag tag;
	DERSequence var_60;
	DERDecodedInfo var_50;
	DERDecodedInfo var_38;
	
	if (a1 == NULL || a4 == NULL) {
		return DR_ParamErr;
	}
	
	rv = DERDecodeSeqInit(a1, &tag, &var_60);
	if (rv) {
		return rv;
	}
	
	if (tag != ASN1_CONSTR_SEQUENCE) {
		return DR_UnexpectedTag;
	}
	
	rv = DERDecodeSeqNext(&var_60, &var_38);
	if (rv) {
		return rv;
	}
	
	if (var_38.tag != ASN1_IA5_STRING) {
		return DR_UnexpectedTag;
	}
	
	rv = DERParseInteger(&var_38.content, &var_6C);
	if (rv) {
		return rv;
	}
	
	if ((E000000000000000 | var_6C) != etag) {
		return DR_UnexpectedTag;
	}
	
	a4[0].item = var_38.content;
	
	rv = DERDecodeSeqNext(&var_60, &var_50);
	if (rv) {
		return rv;
	}
	
	a4[1].tag = var_50.tag;
	a4[1].item = var_50.content;
	
	rv = DERDecodeSeqNext(&var_60, &var_50);
	if (rv != DR_EndOfSequence) {
		return DR_UnexpectedTag;
	}
	return 0;
}

static int DERImg4DecodeFindProperty(const DERItem *a1, DERTag etag, DERTag atag, DERMonster *dest)
{
	int rv;
	DERItemSpec var_70[2];
	uint32_t var_3C;
	DERItem var_38;
	
	rv = DERImg4DecodeContentFindItemWithTag(a1, etag, &var_38);
	if (rv) {
		return rv;
	}
	
	var_70[0].offset = 0;
	var_70[0].tag = ASN1_IA5_STRING;
	var_70[0].options = 0;
	var_70[1].offset = sizeof(DERMonster);
	var_70[1].tag = atag;
	var_70[1].options = 0;
	
	rv = DERParseSequence(&var_38, 2, var_70, dest, 0);
	if (rv) {
		return rv;
	}
	
	rv = DERParseInteger(&dest[0].item, &var_3C);
	if (rv) {
		return rv;
	}
	
	if ((E000000000000000 | var_3C) != etag) {
		return DR_UnexpectedTag;
	}
	
	dest[0].tag = etag | E000000000000000;
	dest[1].tag = atag;
	return 0;
}

static int Img4DecodeGetPropertyData(const DERItem *a1, DERTag tag, DERByte **a4, DERSize *a5)
{
	int rv;
	DERItem var_50;
	DERMonster var_40[2];
	
	var_50.data = a1->data;
	var_50.length = a1->length;
	
	rv = DERImg4DecodeProperty(&var_50, E000000000000000 | tag, var_40);
	if (rv) {
		return rv;
	}
	
	if (var_40[1].tag != ASN1_OCTET_STRING) {
		return DR_UnexpectedTag;
	}
	
	*a4 = var_40[1].item.data;
	*a5 = var_40[1].item.length;
	return 0;
}

int Img4DecodeGetPropertyInteger64(const DERItem *a1, DERTag tag, uint64_t *value)
{
	int rv;
	DERItem var_50;
	DERMonster var_40[2];
	
	var_50.data = a1->data;
	var_50.length = a1->length;
	
	rv = DERImg4DecodeProperty(&var_50, E000000000000000 | tag, var_40);
	if (rv) {
		return rv;
	}
	
	if (var_40[1].tag != ASN1_INTEGER) {
		return DR_UnexpectedTag;
	}
	
	return DERParseInteger64(&var_40[1].item, value);
}

static int Img4ManifestGetDigest(const TheImg4Manifest *m, const unsigned int type, DERByte** hash, DERSize *hash_len)
{
	int rv;
	DERDecodedInfo var_88;
	DERMonster var_70[2];
	DERItem manb, manp, objp;
	
	rv = DERDecodeItem(&m->theset, &var_88);
	if (rv) {
		return rv;
	}
	if (var_88.tag != ASN1_CONSTR_SET) {
		return -1;
	}
	
	rv = DERImg4DecodeFindProperty(&var_88.content, (DERTag)(E000000000000000 | 'MANB'), ASN1_CONSTR_SET, var_70);
	if (rv) {
		return rv;
	}
	manb = var_70[1].item;
	
	rv = DERImg4DecodeFindProperty(&manb, (DERTag)(E000000000000000 | 'MANP'), ASN1_CONSTR_SET, var_70);
	if (rv) {
		return rv;
	}
	manp = var_70[1].item;
	
	rv = DERImg4DecodeFindProperty(&manb, E000000000000000 | type, ASN1_CONSTR_SET, var_70);
	if (rv) {
		return rv;
	}
	objp = var_70[1].item;
	
	DERMonster var_98[2];
	DERItem var_68;
	DERSequence var_58;
	DERDecodedInfo var_48;
	rv = DERDecodeSeqContentInit(&objp, &var_58);
	if (rv) {
		return rv;
	}
	while (1) {
		rv = DERDecodeSeqNext(&var_58, &var_48);
		if (rv == DR_EndOfSequence) {
			return 0;
		}
		if (rv) {
			return rv;
		}
		rv = DERImg4DecodeProperty(&var_48.content, var_48.tag, var_98);
		if (rv) {
			return rv;
		}
		
		if (var_98[1].tag != ASN1_OCTET_STRING && var_98[1].tag != ASN1_INTEGER && var_98[1].tag != ASN1_BOOLEAN) {
			return DR_UnexpectedTag;
		}
		
		if ((var_48.tag & E000000000000000) == 0) {
			return DR_UnexpectedTag;
		}
		
		var_68.data = var_48.content.data;
		var_68.length = var_48.content.length;
		
		if ((unsigned int)var_48.tag == 'DGST') {
			DERSize var_1C;
			DERByte *var_18;
			rv = Img4DecodeGetPropertyData(&var_68, var_48.tag, &var_18, &var_1C);
			if (rv) {
				return rv;
			}
			
			size_t _hash_len = var_1C;
			uint8_t* _hash = malloc(var_1C);
			if (!_hash) {
				logger(LL_ERROR, "malloc failed\n");
				return -40;
			}
			memcpy(_hash, var_18, var_1C);
			var_18 = NULL;
			var_1C = 0;
			
			uint8_t* my_hash = (uint8_t*)_hash;
			fprintf(stderr, "manifest DGST: ");
			for (int i = 0; i < _hash_len; i++) {
				fprintf(stderr, "%02x", my_hash[i]);
			}
			fprintf(stderr, "\n");
			
			if (hash) *hash = _hash;
			if (hash_len) *hash_len = _hash_len;
			return 0;
		}
		return -41;
	}
	return -42;
}

static int Img4ManifestGetBootNonceHash(const TheImg4Manifest *m, DERByte** hash, DERSize *hash_len)
{
	int rv;
	DERDecodedInfo var_88;
	DERMonster var_70[2];
	DERItem manb, manp, objp;
	
	rv = DERDecodeItem(&m->theset, &var_88);
	if (rv) {
		return rv;
	}
	if (var_88.tag != ASN1_CONSTR_SET) {
		return -1;
	}
	
	rv = DERImg4DecodeFindProperty(&var_88.content, (DERTag)(E000000000000000 | 'MANB'), ASN1_CONSTR_SET, var_70);
	if (rv) {
		return rv;
	}
	manb = var_70[1].item;
	
	rv = DERImg4DecodeFindProperty(&manb, (DERTag)(E000000000000000 | 'MANP'), ASN1_CONSTR_SET, var_70);
	if (rv) {
		return rv;
	}
	manp = var_70[1].item;
	
	objp = manp;
	DERMonster var_98[2];
	DERItem var_68;
	DERSequence var_58;
	DERDecodedInfo var_48;
	rv = DERDecodeSeqContentInit(&objp, &var_58);
	if (rv) {
		return rv;
	}
	
	while (1) {
		rv = DERDecodeSeqNext(&var_58, &var_48);
		if (rv == DR_EndOfSequence) {
			return 0;
		}
		if (rv) {
			return rv;
		}
		rv = DERImg4DecodeProperty(&var_48.content, var_48.tag, var_98);
		if (rv) {
			return rv;
		}
		if (var_98[1].tag != ASN1_OCTET_STRING && var_98[1].tag != ASN1_INTEGER && var_98[1].tag != ASN1_BOOLEAN) {
			return DR_UnexpectedTag;
		}
		
		if ((var_48.tag & E000000000000000) == 0) {
			return DR_UnexpectedTag;
		}
		
		var_68.data = var_48.content.data;
		var_68.length = var_48.content.length;
		
		if ((unsigned int)var_48.tag == 'BNCH') {
			DERSize var_1C;
			DERByte *var_18;
			rv = Img4DecodeGetPropertyData(&var_68, var_48.tag, &var_18, &var_1C);
			if (rv) {
				return rv;
			}
			
			size_t _hash_len = var_1C;
			uint8_t* _hash = malloc(var_1C);
			if (!_hash) {
				logger(LL_ERROR, "malloc failed\n");
				return -40;
			}
			memcpy(_hash, var_18, var_1C);
			var_18 = NULL;
			var_1C = 0;
			
			uint8_t* my_hash = (uint8_t*)_hash;
			fprintf(stderr, "manifest BNCH: ");
			for (int i = 0; i < _hash_len; i++) {
				fprintf(stderr, "%02x", my_hash[i]);
			}
			fprintf(stderr, "\n");
			
			if (hash) *hash = _hash;
			if (hash_len) *hash_len = _hash_len;
			return 0;
		}
	}
	return -42;
}

static int Img4ManifestGetECID(const TheImg4Manifest *m, uint64_t* ecid)
{
	int rv;
	DERDecodedInfo var_88;
	DERMonster var_70[2];
	DERItem manb, manp, objp;
	
	rv = DERDecodeItem(&m->theset, &var_88);
	if (rv) {
		return rv;
	}
	if (var_88.tag != ASN1_CONSTR_SET) {
		return -1;
	}
	
	rv = DERImg4DecodeFindProperty(&var_88.content, (DERTag)(E000000000000000 | 'MANB'), ASN1_CONSTR_SET, var_70);
	if (rv) {
		return rv;
	}
	manb = var_70[1].item;
	
	rv = DERImg4DecodeFindProperty(&manb, (DERTag)(E000000000000000 | 'MANP'), ASN1_CONSTR_SET, var_70);
	if (rv) {
		return rv;
	}
	manp = var_70[1].item;
	
	objp = manp;
	DERMonster var_98[2];
	DERItem var_68;
	DERSequence var_58;
	DERDecodedInfo var_48;
	rv = DERDecodeSeqContentInit(&objp, &var_58);
	if (rv) {
		return rv;
	}
	
	while (1) {
		rv = DERDecodeSeqNext(&var_58, &var_48);
		if (rv == DR_EndOfSequence) {
			return 0;
		}
		if (rv) {
			return rv;
		}
		rv = DERImg4DecodeProperty(&var_48.content, var_48.tag, var_98);
		if (rv) {
			return rv;
		}
		
		if (var_98[1].tag != ASN1_OCTET_STRING && var_98[1].tag != ASN1_INTEGER && var_98[1].tag != ASN1_BOOLEAN) {
			return DR_UnexpectedTag;
		}
		
		if ((var_48.tag & E000000000000000) == 0) {
			return DR_UnexpectedTag;
		}
		
		var_68.data = var_48.content.data;
		var_68.length = var_48.content.length;
		
		if ((unsigned int)var_48.tag == 'ECID') {
			uint64_t var_18 = 0;
			rv = Img4DecodeGetPropertyInteger64(&var_68, var_48.tag, &var_18);
			if (rv) {
				return rv;
			}
			logger(LL_DEBUG, "manifest ECID: %016" PRIx64 "\n", var_18);
			if (ecid) *ecid = var_18;
			return 0;
		}
	}
	return -42;
}


static int get_im4p_hash(struct idevicerestore_client_t* client, const char *compname, const uint8_t* payload, const size_t payload_len, uint8_t** hash, size_t* hash_len)
{
	uint8_t* _hash = NULL;
	size_t _hash_len = 0;
	
	if (client->cpid == 0x8010 || client->cpid == 0x8011) {
		unsigned char tsha384[SHA384_DIGEST_LENGTH];
		memset(tsha384, 0, SHA384_DIGEST_LENGTH);
		sha384_context sha384ctx;
		sha384_init(&sha384ctx);
		sha384_update(&sha384ctx, payload, payload_len);
		sha384_final(&sha384ctx, tsha384);
		_hash_len = SHA384_DIGEST_LENGTH;
		_hash = malloc(_hash_len);
		if (!_hash) {
			logger(LL_ERROR, "malloc failed\n");
			return -1;
		}
		memset(_hash, 0, _hash_len);
		memcpy(_hash, tsha384, SHA384_DIGEST_LENGTH);
	}
	else if (client->cpid == 0x7000 || client->cpid == 0x7001 || client->cpid == 0x8000 || client->cpid == 0x8001 || client->cpid == 0x8003) {
		unsigned char tsha1[SHA1_DIGEST_LENGTH];
		memset(tsha1, 0, SHA1_DIGEST_LENGTH);
		sha1_context sha1ctx;
		sha1_init(&sha1ctx);
		sha1_update(&sha1ctx, payload, payload_len);
		sha1_final(&sha1ctx, tsha1);
		_hash_len = SHA1_DIGEST_LENGTH;
		_hash = malloc(_hash_len);
		if (!_hash) {
			logger(LL_ERROR, "malloc failed\n");
			return -1;
		}
		memset(_hash, 0, _hash_len);
		memcpy(_hash, tsha1, SHA1_DIGEST_LENGTH);
	}
	else {
		logger(LL_ERROR, "Found unknown device\n");
		return -1;
	}
	
	uint8_t* my_hash = (uint8_t*)_hash;
	fprintf(stderr, "%s hash: ", compname);
	for (int i = 0; i < _hash_len; i++) {
		fprintf(stderr, "%02x", my_hash[i]);
	}
	fprintf(stderr, "\n");
	
	if (hash) *hash = _hash;
	if (hash_len) *hash_len = _hash_len;
	return 0;
}

int get_img4_digest_from_manifest(struct idevicerestore_client_t* client, plist_t build_identity, const char *compname, const uint8_t* manifest, const size_t manifest_len, uint8_t** hash, size_t* hash_len)
{
	int rv = -16;
	
	if (!client || !build_identity || !compname || !manifest || !manifest_len) {
		return -16;
	}
	
	uint8_t* mhash = NULL;
	size_t mhash_len = 0;
	uint32_t type = 0;
	
	if (!build_identity_has_component(build_identity, compname)) {
		rv = -17;
		goto err;
	}
	
	if (get_img4_type_tag(compname, &type)) {
		logger(LL_ERROR, "Unable to get %s image4 type tag\n", compname);
		rv = -18;
		goto err;
	}
	
	DERItem tmp = { .data = (DERByte *)manifest, .length = manifest_len };
	TheImg4Manifest m;
	if (DERImg4DecodeManifest(&tmp, &m)) {
		logger(LL_ERROR, "Failed to decode image4 manifest\n");
		rv = -19;
		goto err;
	}
	
	if (Img4ManifestGetDigest(&m, type, (DERByte **)&mhash, (DERSize *)&mhash_len)) {
		logger(LL_ERROR, "Failed to get digest from image4 manifest\n");
		rv = 2;
		goto res;
	}
	
	rv = 0;
	
res:
	if (hash) *hash = mhash;
	if (hash_len) *hash_len = mhash_len;
err:
	return rv;
}

int get_boot_nonce_hash_from_manifest(struct idevicerestore_client_t* client, const uint8_t* manifest, const size_t manifest_len, uint8_t** boot_nonce_hash, size_t *nonce_hash_length)
{
	int rv = -16;
	
	if (!client || !manifest || !manifest_len) {
		return -16;
	}
	
	uint8_t* bhash = NULL;
	size_t bhash_len = 0;
	DERItem tmp = { .data = (DERByte *)manifest, .length = manifest_len };
	TheImg4Manifest m;
	if (DERImg4DecodeManifest(&tmp, &m)) {
		logger(LL_ERROR, "Failed to decode image4 manifest\n");
		rv = -19;
		goto err;
	}
	
	if (Img4ManifestGetBootNonceHash(&m, (DERByte **)&bhash, (DERSize *)&bhash_len)) {
		logger(LL_ERROR, "Failed to get boot-nonce hash from image4 manifest\n");
		rv = 2;
		goto res;
	}
	
	rv = 0;
	
res:
	if (boot_nonce_hash) *boot_nonce_hash = bhash;
	if (nonce_hash_length) *nonce_hash_length = bhash_len;
err:
	return rv;
}

int validate_boot_nonce_hash(struct idevicerestore_client_t* client)
{
	int rv = -1;
	if (!client) {
		return rv;
	}
	if (!client->nonce) {
		logger(LL_ERROR, "no ApNonce\n");
		return rv;
	}
	
	plist_t tss_data = NULL;
	char* im4m_data = NULL;
	uint64_t im4m_data_len = 0;
	uint8_t* boot_nonce_hash = NULL;
	size_t nonce_hash_size = 0;
	
	tss_data = plist_copy(client->local_shsh);
	if (!tss_data) {
		logger(LL_ERROR, "local TSS data not found\n");
		rv = -2;
		goto end;
	}
	
	plist_t apimg4ticket = plist_dict_get_item(tss_data, "ApImg4Ticket");
	if (!apimg4ticket) {
		logger(LL_ERROR, "no ApImg4Ticket dict\n");
		rv = -3;
		goto end;
	}
	
	plist_get_data_val(apimg4ticket, &im4m_data, &im4m_data_len);
	if (!im4m_data) {
		logger(LL_ERROR, "no img4 manifest\n");
		rv = -4;
		goto end;
	}
	
	if (get_boot_nonce_hash_from_manifest(client, (const uint8_t*)im4m_data, (const size_t)im4m_data_len, &boot_nonce_hash, &nonce_hash_size)) {
		logger(LL_ERROR, "Unable to get boot-nonce hash from manifest\n");
		rv = -5;
		goto end;
	}
	
	if (!boot_nonce_hash) {
		logger(LL_ERROR, "no boot-nonce hash\n");
		rv = -6;
		goto end;
	}
	
	if (client->nonce_size != nonce_hash_size) {
		logger(LL_ERROR, "wrong boot-nonce hash size (%d != %d)\n", client->nonce_size, (int)nonce_hash_size);
		rv = -7;
		goto end;
	}
	
	fprintf(stderr, "ApNonce: ");
	int i;
	for (i = 0; i < client->nonce_size; i++) {
		fprintf(stderr, "%02x", client->nonce[i]);
	}
	fprintf(stderr, "\n");
	fprintf(stderr, "BNCH: ");
	for (i = 0; i < nonce_hash_size; i++) {
		fprintf(stderr, "%02x", boot_nonce_hash[i]);
	}
	fprintf(stderr, "\n");
	
	if (memcmp(boot_nonce_hash, client->nonce, nonce_hash_size)) {
		logger(LL_ERROR, "Unexpected boot-nonce hash\n");
		rv = -8;
		goto end;
	}
	
	rv = 0;
	
end:
	if (tss_data) plist_free(tss_data);
	if (im4m_data) free(im4m_data);
	if (boot_nonce_hash) free(boot_nonce_hash);
	return rv;
}

static int get_ECID_from_manifest(struct idevicerestore_client_t* client, const uint8_t* manifest, const size_t manifest_len, uint64_t* ecid)
{
	int rv = -16;
	
	if (!client || !manifest || !manifest_len) {
		return -16;
	}
	
	DERItem tmp = { .data = (DERByte *)manifest, .length = manifest_len };
	TheImg4Manifest m;
	if (DERImg4DecodeManifest(&tmp, &m)) {
		logger(LL_ERROR, "Failed to decode image4 manifest\n");
		rv = -19;
		goto err;
	}
	
	if (Img4ManifestGetECID(&m, ecid)) {
		logger(LL_ERROR, "Failed to get ECID from image4 manifest\n");
		rv = 2;
		goto err;
	}
	
	rv = 0;
	
err:
	return rv;
}

int validate_ECID(struct idevicerestore_client_t* client)
{
	int rv = -1;
	if (!client) {
		return rv;
	}
	if (!client->ecid) {
		logger(LL_ERROR, "no ECID\n");
		return rv;
	}
	
	plist_t tss_data = NULL;
	char* im4m_data = NULL;
	uint64_t im4m_data_len = 0;
	uint64_t im4m_ecid = 0;
	tss_data = plist_copy(client->local_shsh);
	if (!tss_data) {
		logger(LL_ERROR, "local TSS data not found\n");
		rv = -2;
		goto end;
	}
	
	plist_t apimg4ticket = plist_dict_get_item(tss_data, "ApImg4Ticket");
	if (!apimg4ticket) {
		logger(LL_ERROR, "no ApImg4Ticket dict\n");
		rv = -3;
		goto end;
	}
	
	plist_get_data_val(apimg4ticket, &im4m_data, &im4m_data_len);
	if (!im4m_data) {
		logger(LL_ERROR, "no img4 manifest\n");
		rv = -4;
		goto end;
	}
	
	if (get_ECID_from_manifest(client, (const uint8_t*)im4m_data, (const size_t)im4m_data_len, &im4m_ecid)) {
		logger(LL_ERROR, "Unable to get ECID from manifest\n");
		rv = -5;
		goto end;
	}
	
	logger(LL_INFO, "Device ECID: %016" PRIx64 "\n", client->ecid);
	logger(LL_INFO, "IM4M ECID: %016" PRIx64 "\n", im4m_ecid);
	
	if (client->ecid != im4m_ecid) {
		logger(LL_ERROR, "ECID mismatch detected\n");
		rv = -8;
		goto end;
	}
	
	rv = 0;
	
end:
	if (tss_data) plist_free(tss_data);
	if (im4m_data) free(im4m_data);
	return rv;
}

int validate_img4_digest(struct idevicerestore_client_t* client, plist_t build_identity, const char *compname, const uint8_t* payload, const size_t payload_len, const uint8_t* manifest, const size_t manifest_len, bool verify_manifest, bool verify_payload, uint32_t* result)
{
	int rv = -16;
	if (!client || !build_identity || !compname) {
		return -16;
	}
	
	uint32_t _result = IMG4_DIGEST_ERROR;
	
	uint8_t* digest = NULL;
	size_t digest_len = 0;
	uint8_t* hash = NULL;
	size_t hash_len = 0;
	uint8_t* mhash = NULL;
	size_t mhash_len = 0;
	uint32_t type = 0;
	
	if (!build_identity_has_component(build_identity, compname)) {
		rv = -17;
		goto err;
	}
	
	if (build_identity_get_component_digest(build_identity, compname, &digest, &digest_len)) {
		logger(LL_ERROR, "Unable to find digest data\n");
		rv = -18;
		goto err;
	}
	
	if (verify_payload) {
		if (!payload || !payload_len) {
			logger(LL_ERROR, "Unable to find image4 payload\n");
			rv = -19;
			goto err;
		}
	}
	
	if (verify_manifest) {
		if (!manifest || !manifest_len) {
			logger(LL_ERROR, "Unable to find image4 manifest\n");
			rv = -20;
			goto err;
		}
	}
	
	if (get_img4_type_tag(compname, &type)) {
		logger(LL_ERROR, "Unable to get %s image4 type tag\n", compname);
		rv = -21;
		goto err;
	}
	
	// Here we check whether the digest hash in the ipsw's BuildManifest and the img4 payload match.
	if (verify_payload) {
		uint32_t _type = 0;
		if (get_img4_payload_tag(compname, payload, &_type)) {
			logger(LL_ERROR, "Unable to get image4 payload type tag\n");
			rv = -22;
			goto err;
		}
		if (_type != type) {
			logger(LL_ERROR, "image4 type tag does not match (%08x != %08x)\n", _type, type);
			rv = -23;
			goto err;
		}
		if (get_im4p_hash(client, compname, payload, payload_len, &hash, &hash_len)) {
			logger(LL_ERROR, "Unable to get image4 payload hash\n");
			rv = -24;
			goto err;
		}
		if (hash_len != digest_len) {
			logger(LL_ERROR, "Hash size does not match\n");
			rv = -25;
			goto err;
		}
		// check hash
		if (memcmp(digest, hash, digest_len)) {
			logger(LL_INFO, "Hash does not match\n");
			_result |= IMG4_DIGEST_VALID_PAYLOAD;
		}
		else {
			_result |= (IMG4_DIGEST_VALID_PAYLOAD | IMG4_DIGEST_MATCHED_PAYLOAD);
		}
	}
	
	if (verify_manifest) {
		DERItem tmp = { .data = (DERByte *)manifest, .length = manifest_len };
		TheImg4Manifest m;
		if (DERImg4DecodeManifest(&tmp, &m)) {
			logger(LL_ERROR, "Failed to decode image4 manifest\n");
			rv = -26;
			goto err;
		}
		
		if (Img4ManifestGetDigest(&m, type, (DERByte **)&mhash, (DERSize *)&mhash_len)) {
			logger(LL_INFO, "Failed to get digest from image4 manifest\n");
			rv = 2;
			goto res;
		}
		
		if (mhash_len != digest_len) {
			logger(LL_ERROR, "Hash size does not match\n");
			rv = -27;
			goto err;
		}
		if (memcmp(digest, mhash, digest_len)) {
			logger(LL_INFO, "Hash does not match\n");
			_result |= IMG4_DIGEST_VALID_MANIFEST;
		}
		else {
			_result |= (IMG4_DIGEST_VALID_MANIFEST | IMG4_DIGEST_MATCHED_MANIFEST);
		}
	}
	
	rv = 0;
	
res:
	if (result) *result = _result;
	
err:
	if (digest) free(digest);
	if (hash) free(hash);
	if (mhash) free(mhash);
	return rv;
}

int get_image4_manifest_hash(const uint8_t* manifest, const size_t manifest_len, uint32_t type, uint8_t** hash, size_t* hash_len)
{
	int rv = -16;
	uint8_t* mhash = NULL;
	size_t mhash_len = 0;
	
	if (!manifest || !manifest_len || !type) {
		return rv;
	}
	
	DERItem tmp = { .data = (DERByte *)manifest, .length = manifest_len };
	TheImg4Manifest m;
	if (DERImg4DecodeManifest(&tmp, &m)) {
		logger(LL_ERROR, "Failed to decode image4 manifest\n");
		rv = -26;
		goto err;
	}
	
	if (Img4ManifestGetDigest(&m, type, (DERByte **)&mhash, (DERSize *)&mhash_len)) {
		logger(LL_INFO, "Failed to get digest from image4 manifest\n");
		rv = 2;
		goto err;
	}
	
	if (mhash_len > 0x30) {
		logger(LL_ERROR, "Too large hash size\n");
		rv = -28;
		goto err;
	}
	
	if (hash && hash_len) {
		uint8_t* _hash = malloc(mhash_len);
		if (!_hash) {
			logger(LL_ERROR, "malloc failed\n");
			rv = -28;
			goto err;
		}
		memcpy(_hash, mhash, mhash_len);
		*hash = _hash;
		*hash_len = mhash_len;
	}
	
	rv = 0;
	
err:
	if (mhash) free(mhash);
	return rv;
}

#pragma mark - restore
int recovery_send_ramdisk_component(struct idevicerestore_client_t* client, plist_t build_identity, const char* component)
{
	size_t size = 0;
	unsigned char* data = NULL;
	char* path = NULL;
	irecv_error_t err = 0;
	
	if (client->tss) {
		if (tss_response_get_path_by_entry(client->tss, component, &path) < 0) {
			logger(LL_DEBUG, "NOTE: No path for component %s in TSS, will fetch from build_identity\n", component);
		}
	}
	if (!path) {
		if (build_identity_get_component_path(build_identity, component, &path) < 0) {
			logger(LL_ERROR, "Unable to get path for component '%s'\n", component);
			free(path);
			return -1;
		}
	}
	
	unsigned char* component_data = NULL;
	size_t component_size = 0;
	int ret = extract_component(client->ipsw, path, (void **)&component_data, &component_size);
	free(path);
	if (ret < 0) {
		logger(LL_ERROR, "Unable to extract component: %s\n", component);
		return -1;
	}
	
	if (client->flags & FLAG_TETHERED && is_armv7s_soc(client->cpid)) {
		if (client->build_major == 14) {
#ifdef HAVE_LIBHFSPLUS
			if (component_size < 0x40) {
				logger(LL_ERROR, "Too small component: %s\n", component);
				return -1;
			}
			uint32_t img3__magic = read_u32_le(component_data);
			uint32_t img3__ident = read_u32_le(component_data + 0x10);
			uint32_t img3__DATA_dataLength = read_u32_le(component_data + 0x3c);
			if (img3__magic == 0x496D6733u) {
				logger(LL_INFO, "Found image3\n");
				if (img3__ident == 0x7264736Bu) {
					logger(LL_INFO, "Found rdsk\n");
					if (component_size < img3__DATA_dataLength) {
						logger(LL_ERROR, "Wrong image3 struct: %s\n", component);
						return -1;
					}
					void* ramdiskbuf = malloc(img3__DATA_dataLength);
					memcpy(ramdiskbuf, component_data + 0x40, img3__DATA_dataLength);
					if (!patchASR(ramdiskbuf, img3__DATA_dataLength)) {
						logger(LL_INFO, "Patch done!\n");
						memcpy(component_data + 0x40, ramdiskbuf, img3__DATA_dataLength);
					}
				}
			}
#else
			logger(LL_ERROR, "Restoring to this version is not supported.\n");
			return -1;
#endif
		}
	}
	
	ret = personalize_component(client, component, component_data, component_size, client->tss, (void **)&data, &size);
	free(component_data);
	if (ret < 0) {
		logger(LL_ERROR, "Unable to get personalized component: %s\n", component);
		return -1;
	}
	
	logger(LL_INFO, "Sending %s (%zu bytes)...\n", component, size);
	
	// FIXME: Did I do this right????
	err = irecv_send_buffer(client->recovery->client, data, size, 0);
	free(data);
	if (err != IRECV_E_SUCCESS) {
		logger(LL_ERROR, "Unable to send %s component: %s\n", component, irecv_strerror(err));
		return -1;
	}
	
	return 0;
}

int get_cryptex1_local_cache(struct idevicerestore_client_t* client, plist_t* tss)
{
	plist_t request = NULL;
	plist_t response = NULL;
	*tss = NULL;
	
	if (client->restore->cryptex1tss) {
		*tss = plist_copy(client->restore->cryptex1tss);
		logger(LL_INFO, "Using cached SHSH\n");
		return 0;
	}
	
	/* first check for local copy */
	char zfn[1024];
	if (client->version) {
		if (client->cache_dir) {
			snprintf(zfn, sizeof(zfn), "%s/shsh/%" PRIu64 "-%s-%s-cryptex.shsh", client->cache_dir, client->ecid, client->device->product_type, client->version);
		}
		else {
			snprintf(zfn, sizeof(zfn), "shsh/%" PRIu64 "-%s-%s-cryptex.shsh", client->ecid, client->device->product_type, client->version);
		}
		struct stat fst;
		if (stat(zfn, &fst) == 0) {
			gzFile zf = gzopen(zfn, "rb");
			if (zf) {
				size_t blen = 0;
				size_t readsize = 16384;
				size_t bufsize = readsize;
				char* bin = (char*)malloc(bufsize);
				if (bin == NULL) {
					logger(LL_ERROR, "Out of memory\n");
					gzclose(zf);
					return -1;
				}
				char* p = bin;
				do {
					int bytes_read = gzread(zf, p, readsize);
					if (bytes_read < 0) {
						logger(LL_ERROR, "Reading gz compressed data\n");
						if (bin) {
							free(bin);
						}
						gzclose(zf);
						return -1;
					}
					blen += bytes_read;
					if (bytes_read < readsize) {
						if (gzeof(zf)) {
							bufsize += bytes_read;
							break;
						}
					}
					bufsize += readsize;
					if (bufsize > 0x800000) {
						logger(LL_ERROR, "Too large file\n");
						if (bin) {
							free(bin);
						}
						gzclose(zf);
						return -1;
					}
					char* realloc_bin = realloc(bin, bufsize);
					if (realloc_bin == NULL) {
						logger(LL_ERROR, "realloc failed\n");
						gzclose(zf);
						if (bin) {
							free(bin);
						}
						return -1;
					}
					bin = realloc_bin;
					p = bin + blen;
				} while (!gzeof(zf));
				gzclose(zf);
				if (blen > 0) {
					if (memcmp(bin, "bplist00", 8) == 0) {
						plist_from_bin(bin, blen, tss);
					}
					else {
						plist_from_xml(bin, blen, tss);
					}
				}
				free(bin);
			}
		}
		else {
			logger(LL_INFO, "No local file %s\n", zfn);
		}
	}
	else {
		logger(LL_INFO, "No version found?!\n");
	}
	
	if (*tss) {
		logger(LL_INFO, "Using cached SHSH\n");
		return 0;
	}
	return -1;
}

#pragma mark - dfu
int dfu_get_yolo_checkra1n(struct idevicerestore_client_t* client)
{
	if (client->dfu == NULL) {
		if (dfu_client_new(client) < 0) {
			return -1;
		}
	}
	
	const struct irecv_device_info *device_info = irecv_get_device_info(client->dfu->client);
	if (!device_info) {
		return -1;
	}
	char* ptr = strstr(device_info->serial_string, "YOLO:checkra1n");
	if (ptr) {
		return 0;
	}
	return -1;
}

int dfu_get_pwned_dfu(struct idevicerestore_client_t* client)
{
	if (client->dfu == NULL) {
		if (dfu_client_new(client) < 0) {
			return -1;
		}
	}
	
	const struct irecv_device_info *device_info = irecv_get_device_info(client->dfu->client);
	if (!device_info) {
		return -1;
	}
	char* ptr = strstr(device_info->serial_string, "PWND:[yolo]");
	if (ptr) {
		return 0;
	}
	return -1;
}
