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

#include <libfragmentzip/libfragmentzip.h>
#include <libimobiledevice-glue/sha.h>
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

#pragma mark - global
void fragmentzip_callback(unsigned int p)
{
	int i = 0;
	int width = 50;
	int filled = (p * width) / 100;
	printf("\r%s [", "Downloading");
	for (i = 0; i < width; i++) {
		if (i < filled) {
			putchar('=');
		}
		else {
			putchar(' ');
		}
	}
	printf("] %3u%%", p);
	fflush(stdout);
	if (p >= 100) {
		printf("\n");
	}
}

#pragma mark - common
int read_aligned_file_safe(const char* filename, void** data, size_t* size, size_t max_size)
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
	
	void* tmp_buffer = NULL;
	int res = posix_memalign(&tmp_buffer, sizeof(uint64_t), length);
	if (res != 0) {
		logger(LL_ERROR, "memalign failed (reason: %s)", strerror(res));
		fclose(file);
		return -1;
	}
	if (tmp_buffer == NULL) {
		logger(LL_ERROR, "Out of memory\n");
		fclose(file);
		return -1;
	}
	
	buffer = (char*)tmp_buffer;
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

void print_module_hash(const char* name, const char* type, const uint8_t* buf, const size_t length)
{
	unsigned char tsha384[SHA384_DIGEST_LENGTH];
	memset(tsha384, 0, SHA384_DIGEST_LENGTH);
	sha384_context sha384ctx;
	sha384_init(&sha384ctx);
	sha384_update(&sha384ctx, buf, length);
	sha384_final(&sha384ctx, tsha384);
	
	for (int i = 0; i < SHA384_DIGEST_LENGTH; i++) {
		printf("%02x", tsha384[i]);
	}
	printf(" = SHA384(%s.%s) hash (%zu bytes)\n", name, type, length);
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

#pragma mark - idevicerestore
int load_firmware_component_data(const char* path, firmware_component_t* comp, const char* name)
{
	if (!path || !*path) {
		logger(LL_ERROR, "PATH argument for --%s must not be empty!\n", name);
		return -1;
	}
	if (comp->data) {
		free(comp->data);
		comp->data = NULL;
		comp->length = 0;
	}
	if (read_file_safe(path, (void**)&comp->data, &comp->length, 0x8000000) != 0) {
		return -1;
	}
	return 0;
}

int load_firmware_component_plist(const char* path, firmware_component_t* comp, const char* name)
{
	if (!path || !*path) {
		logger(LL_ERROR, "PATH argument for --%s-manifest must not be empty!\n", name);
		return -1;
	}
	
	if (comp->manifest) {
		plist_free(comp->manifest);
		comp->manifest = NULL;
	}
	
	uint8_t* bin = NULL;
	size_t len = 0;
	if (read_file_safe(path, (void**)&bin, &len, 0x4000000) != 0) {
		return -1;
	}
	
	if (len >= 8 && memcmp(bin, "bplist00", 8) == 0) {
		plist_from_bin((const char *)bin, len, &comp->manifest);
	}
	else {
		plist_from_xml((const char *)bin, len, &comp->manifest);
	}
	free(bin);
	return (comp->manifest) ? 0 : -1;
}

int get_identity_for_component(struct idevicerestore_client_t* client, firmware_component_t* comp)
{
	if (comp->manifest == NULL) {
		logger(LL_ERROR, "Unable to find Manifest\n");
		return -1;
	}
	if (comp->variant) {
		const char* hwmodel = comp->alternative_hwmodel != NULL ? (const char*)comp->alternative_hwmodel : client->device->hardware_model;
		comp->identity = build_manifest_get_build_identity_for_model_with_variant(comp->manifest, hwmodel, comp->variant, 1);
	}
	else {
		comp->identity = build_manifest_get_build_identity_for_model_with_variant(comp->manifest, client->device->hardware_model, RESTORE_VARIANT_ERASE_INSTALL, 0);
	}
	if (comp->identity == NULL) {
		return -1;
	}
	return 0;
}

int download_component_by_name(fragmentzip_t* fragment, const char* name, const char* altname, firmware_component_t* comp)
{
	const char* basename = NULL;
	char* value = NULL;
	plist_t manifest_node = NULL;
	plist_t component_node = NULL;
	plist_t info_node = NULL;
	plist_t node = NULL;
	if (comp->identity == NULL) {
		logger(LL_ERROR, "Unable to find Manifest identity\n");
		return -1;
	}
	if (name == NULL) {
		logger(LL_ERROR, "Unable to find node name\n");
		return -1;
	}
	if (fragment == NULL) {
		logger(LL_ERROR, "Unable to find fragmentzip\n");
		return -1;
	}
	manifest_node = plist_dict_get_item(comp->identity, "Manifest");
	if (!manifest_node || plist_get_node_type(manifest_node) != PLIST_DICT) {
		logger(LL_ERROR, "Unable to find Manifest node\n");
		return -1;
	}
	
	basename = name;
	component_node = plist_dict_get_item(manifest_node, basename);
	if (!component_node || plist_get_node_type(component_node) != PLIST_DICT) {
		if (altname) {
			basename = altname;
			component_node = plist_dict_get_item(manifest_node, basename);
		}
		if (!component_node || plist_get_node_type(component_node) != PLIST_DICT) {
			logger(LL_ERROR, "Unable to find %s node\n", basename);
			return -1;
		}
	}
	
	info_node = plist_dict_get_item(component_node, "Info");
	if (!info_node || plist_get_node_type(info_node) != PLIST_DICT) {
		logger(LL_ERROR, "Unable to find Info node for %s\n", basename);
		return -1;
	}
	
	node = plist_dict_get_item(info_node, "Path");
	if (!node || plist_get_node_type(node) != PLIST_STRING) {
		logger(LL_ERROR, "Unable to find Path node for %s\n", basename);
		return -1;
	}
	plist_get_string_val(node, &value);
	
	logger(LL_INFO, "Downloading %s\n", value);
	char* tmp_buf = NULL;
	size_t tmp_len = 0;
	if (fragmentzip_download_to_memory(fragment, value, &tmp_buf, &tmp_len, fragmentzip_callback)) {
		logger(LL_ERROR, "Could not find %s\n", value);
		free(value);
		return -1;
	}
	if (!tmp_buf) {
		logger(LL_ERROR, "Could not allocate %s buffer\n", value);
		free(value);
		return -1;
	}
	comp->data = (uint8_t*)tmp_buf;
	comp->length = tmp_len;
	logger(LL_DEBUG, "%s length: %zu\n", basename, comp->length);
	free(value);
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
	register_progress('RECV', "Uploading");
	err = irecv_send_buffer(client->recovery->client, data, size, 0);
	free(data);
	finalize_progress('RECV');
	if (err != IRECV_E_SUCCESS) {
		logger(LL_ERROR, "Unable to send %s component: %s\n", component, irecv_strerror(err));
		return -1;
	}
	
	return 0;
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
