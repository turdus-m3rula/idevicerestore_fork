/*
 * idevicerestore.c
 * Restore device firmware and filesystem
 *
 * Copyright (c) 2012-2019 Nikias Bassen. All Rights Reserved.
 * Copyright (c) 2010-2015 Martin Szulecki. All Rights Reserved.
 * Copyright (c) 2010 Joshua Hill. All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <getopt.h>
#include <plist/plist.h>
#include <zlib.h>
#include <libgen.h>
#include <signal.h>

#include <curl/curl.h>

#include <libimobiledevice-glue/sha.h>
#include <libimobiledevice-glue/utils.h>
#include <libimobiledevice-glue/termcolors.h>
#include <libtatsu/tss.h>

#include "ace3.h"
#include "dfu.h"
#include "img3.h"
#include "img4.h"
#include "ipsw.h"
#include "common.h"
#include "normal.h"
#include "restore.h"
#include "download.h"
#include "recovery.h"
#include "idevicerestore.h"

#ifdef HAVE_LIMERA1N
#include "limera1n.h"
#endif

#include "locking.h"

#ifdef HAVE_TURDUS_MERULA
#include <usbmuxd.h>
#include <zip.h>
#include <libfragmentzip/libfragmentzip.h>
#include "turdus/merula.h"
#include "turdus/pongo.h"
#include "stuff/Pongo_bin.h"
#include "stuff/cpf_bin.h"
#include "stuff/kpf_bin.h"
#include "stuff/sep_racer_bin.h"
#include "stuff/overlay_bin.h"
#include "stuff/union_bin.h"
static char* ap_shsh_path = NULL;
#endif

#define VERSION_XML "version.xml"

#ifndef  IDEVICERESTORE_NOMAIN
static struct option longopts[] = {
	{ "ecid",           required_argument, NULL, 'i' },
	{ "udid",           required_argument, NULL, 'u' },
	{ "debug",          no_argument,       NULL, 'd' },
	{ "help",           no_argument,       NULL, 'h' },
	{ "server",         required_argument, NULL, 's' },
	
	{ "cache-path",     required_argument, NULL, 'C' },
	{ "no-input",       no_argument,       NULL, 'y' },
	{ "plain-progress", no_argument,       NULL, 'P' },
	{ "version",        no_argument,       NULL, 'v' },
	{ "ipsw-info",      no_argument,       NULL, 'I' },
	{ "variant",        required_argument, NULL,  2  },
	{ "logfile",        required_argument, NULL,  3  },
	
#ifndef HAVE_TURDUS_MERULA
	{ "erase",          no_argument,       NULL, 'e' },
	{ "custom",         no_argument,       NULL, 'c' },
	{ "latest",         no_argument,       NULL, 'l' },
	{ "exclude",        no_argument,       NULL, 'x' },
	{ "shsh",           no_argument,       NULL, 't' },
	{ "keep-pers",      no_argument,       NULL, 'k' },
#ifdef HAVE_LIMERA1N
	{ "pwn",            no_argument,       NULL, 'p' },
#endif
	{ "no-action",      no_argument,       NULL, 'n' },
	{ "restore-mode",   no_argument,       NULL, 'R' },
	{ "ticket",         required_argument, NULL, 'T' },
	{ "no-restore",     no_argument,       NULL, 'z' },
	{ "ignore-errors",  no_argument,       NULL,  1  },
#endif
	
#ifdef HAVE_TURDUS_MERULA
	{ "downgrade",       no_argument,       NULL, 'w' },
	{ "tethered",        no_argument,       NULL, 'o' },
	
	{ "alternative-hwmodel", required_argument, NULL, 11 },
	{ "bbfw",            required_argument, NULL, 12 },
	{ "bbfw-manifest",   required_argument, NULL, 13 },
	{ "bbfw-variant",    required_argument, NULL, 14 },
	
	{ "sefw",            required_argument, NULL, 15 },
	{ "sefw-manifest",   required_argument, NULL, 16 },
	{ "sefw-variant",    required_argument, NULL, 17 },
	
	{ "rsep",            required_argument, NULL, 18 },
	{ "rsep-manifest",   required_argument, NULL, 19 },
	{ "rsep-variant",    required_argument, NULL, 20 },
	
	{ "base-manifest",   required_argument, NULL, 21 },
	{ "base-variant",    required_argument, NULL, 22 },
	
	{ "load-shsh",       required_argument, NULL, 23  },
	{ "load-shcblock",   required_argument, NULL, 24  },
	{ "load-pteblock",   required_argument, NULL, 25  },
	{ "enable-serial",   no_argument,       NULL, 26  },
	{ "get-shcblock",    no_argument,       NULL, 27  },
	{ "get-pteblock",    no_argument,       NULL, 28  },
	{ "allow-unsupport", no_argument,       NULL, 29  },
	{ "show-hash",       no_argument,       NULL, 30  },
	{ "api-url",         required_argument, NULL, 31  },
	
	{ "override-kpf", required_argument, NULL, 32 },
	{ "override-cpf", required_argument, NULL, 33 },
	{ "override-sep-racer", required_argument, NULL, 34 },
	{ "override-pongo", required_argument, NULL, 35 },
	{ "override-ramdisk", required_argument, NULL, 36 },
#endif
	{ NULL, 0, NULL, 0 }
};

static void usage(int argc, char* argv[], int err)
{
#ifdef HAVE_LIMERA1N
#define PWN_FLAG_LINE  \
"  -p, --pwn                          Put device in pwned DFU mode and exit (limera1n devices)\n"
#else
#define PWN_FLAG_LINE ""
#endif
#ifdef HAVE_TURDUS_MERULA
#define TURDUS_MERULA_FLAG_LINE "\nDowngrade options:\n" \
"  -w, --downgrade              Restore device to an official firmware using saved TSS record (SHSH)\n" \
"                               (The SHSH must match the target firmware version)\n" \
"  -o, --tethered               Restore to any official firmware without a matching TSS record (SHSH)\n" \
"                               Uses the latest signed SHSH instead\n" \
"                               (Requires checkm8 exploit on every reboot)\n" \
"  --load-shsh PATH             Load a custom SHSH from the given PATH\n" \
"  --load-shcblock PATH         Load SEP ciphertext block (shcblock) for A9/A9X devices\n" \
"  --load-pteblock PATH         Load SEP ciphertext block (pteblock) for A9/A9X devices\n" \
"  --enable-serial              Enable serial output during restore\n" \
"  --alternative-hwmodel MODEL  Override hardware model for alternative signed baseband firmware\n" \
"  --bbfw PATH                  Override BasebandFirmware image\n" \
"  --bbfw-manifest PATH         Override BuildManifest for custom BasebandFirmware image\n" \
"  --bbfw-variant VARIANT       Use given VARIANT to match the build identity to use with custom BasebandFirmware image\n" \
"  --sefw PATH                  Override SE Firmware image\n" \
"  --sefw-manifest PATH         Override BuildManifest for custom SE Firmware image\n" \
"  --sefw-variant VARIANT       Use given VARIANT to match the build identity to use with custom SE Firmware image\n" \
"  --rsep PATH                  Override RestoreSEP image4 payload\n" \
"  --rsep-manifest PATH         Override BuildManifest for custom RestoreSEP image4 payload\n" \
"  --rsep-variant VARIANT       Use given VARIANT to match the build identity to use with custom RestoreSEP image4 payload\n" \
"  --base-manifest PATH         Override BuildManifest for base firmware used for tethered downgrade\n" \
"  --base-variant VARIANT       Use given VARIANT to match the build identity to use with base firmware image\n" \
"  --get-shcblock               Acquire shcblock required for SEPROM exploit (fwload race) on A9/A9X devices\n" \
"  --get-pteblock               Acquire pteblock required for SEPROM exploit (boot_tz0 race) on A9/A9X devices\n" \
"  --allow-unsupport            Allow restore to an unsupported firmware version\n" \
"  --api-url URL                Override default API server URL\n" \
"  --override-kpf PATH          Override KPF module\n" \
"  --override-cpf PATH          Override CPF module\n" \
"  --override-sep-racer PATH    Override sep_racer module\n" \
"  --override-pongo PATH        Override Pongo\n" \
"  --override-ramdisk PATH      Override overlay ramdisk\n" \
"  --show-hash                  Show the SHA2-384 hashes of embedded modules\n\n" \
"\nThis is a fork of idevicerestore\n"
#else
#define TURDUS_MERULA_FLAG_LINE ""
#endif
#ifndef HAVE_TURDUS_MERULA
#define NON_TURDUS_MERULA_OPTION_FLAG_LINE "" \
"  -l, --latest                 Use latest available firmware (with download on demand).\n" \
"                               Before performing any action it will interactively ask\n" \
"                               to select one of the currently signed firmware versions,\n" \
"                               unless -y has been given too.\n" \
"                               The PATH argument is ignored when using this option.\n" \
"                               DO NOT USE if you need to preserve the baseband/unlock!\n" \
"                               USE WITH CARE if you want to keep a jailbreakable\n" \
"                               firmware!\n" \
"  -e, --erase                  Perform full restore instead of update, erasing all data\n" \
"                               DO NOT USE if you want to preserve user data on the device!\n" \
"  -n, --no-action              Do not perform any restore action. If combined with -l\n" \
"                               option the on-demand ipsw download is performed before\n" \
"                               exiting.\n"
#define NON_TURDUS_MERULA_ADVANCED_OPTION_FLAG_LINE "" \
"  -c, --custom                 Restore with a custom firmware (requires bootrom exploit)\n" \
"  -x, --exclude                Exclude nor/baseband upgrade (legacy devices)\n" \
"  -t, --shsh                   Fetch TSS record and save to .shsh file, then exit\n" \
"  -z, --no-restore             Do not restore and end after booting to the ramdisk\n" \
"  -k, --keep-pers              Write personalized components to files for debugging\n" \
PWN_FLAG_LINE \
"  -R, --restore-mode           Allow restoring from Restore mode\n" \
"  -T, --ticket PATH            Use file at PATH to send as AP ticket\n" \
"  --ignore-errors              Try to continue the restore process after certain\n" \
"                               errors (like a failed baseband update)\n" \
"                               WARNING: This might render the device unable to boot\n" \
"                               or only partially functioning. Use with caution.\n"
#else
#define NON_TURDUS_MERULA_OPTION_FLAG_LINE ""
#define NON_TURDUS_MERULA_ADVANCED_OPTION_FLAG_LINE ""
#endif
	char* name = strrchr(argv[0], '/');
	fprintf((err) ? stderr : stdout,
	"Usage: %s [OPTIONS] PATH\n" \
	"\n" \
	"Restore IPSW firmware at PATH to an iOS device.\n" \
	"\n" \
	"PATH can be a compressed .ipsw file or a directory containing all files\n" \
	"extracted from an IPSW.\n" \
	"\n" \
	"OPTIONS:\n" \
	"  -i, --ecid ECID                    Target specific device by its ECID\n" \
	"                                     e.g. 0xaabb123456 (hex) or 1234567890 (decimal)\n" \
	"  -u, --udid UDID                    Target specific device by its device UDID\n" \
	"                                     NOTE: only works with devices in normal mode.\n" \
	"  -y, --no-input                     Non-interactive mode, do not ask for any input.\n" \
	"                                     WARNING: This will disable certain checks/prompts that\n" \
	"                                     are supposed to prevent DATA LOSS. Use with caution.\n" \
	"  --ipsw-info                        Print information about the IPSW at PATH and exit.\n" \
	"  -h, --help                         Prints this usage information\n" \
	"  -C, --cache-path DIR               Use specified directory for caching extracted or other\n" \
	"                                     reused files.\n" \
	"  --logfile=PATH                     Write logging output to file at PATH. If PATH equals\n" \
	"                                     'NULL' or 'NONE', no log file will be written.\n" \
	"  -d, --debug                        Print additional debug output\n" \
	"  -v, --version                      Print version information\n" \
	NON_TURDUS_MERULA_OPTION_FLAG_LINE \
	"\n" \
	"Advanced/experimental options:\n"
	"  -s, --server URL                   Override default signing server request URL\n" \
	"  -P, --plain-progress               Print progress as plain step and progress\n" \
	"  --variant VARIANT                  Use given VARIANT to match the build identity to use,\n" \
	"                                     e.g. 'Customer Erase Install (IPSW)'\n" \
	NON_TURDUS_MERULA_ADVANCED_OPTION_FLAG_LINE \
	// Downgrade command
	TURDUS_MERULA_FLAG_LINE \
	"\n" \
	"Homepage:    <" PACKAGE_URL ">\n" \
	"Bug Reports: <" PACKAGE_BUGREPORT ">\n",
	(name ? name + 1 : argv[0]));
}
#endif

const uint8_t lpol_file[22] = {
		0x30, 0x14, 0x16, 0x04, 0x49, 0x4d, 0x34, 0x50,
		0x16, 0x04, 0x6c, 0x70, 0x6f, 0x6c, 0x16, 0x03,
		0x31, 0x2e, 0x30, 0x04, 0x01, 0x00
};
const uint32_t lpol_file_length = 22;

static int load_version_data(struct idevicerestore_client_t* client)
{
	if (!client) {
		return -1;
	}

	struct stat fst;
	int cached = 0;

	char version_xml[1024];

	if (client->cache_dir) {
		if (stat(client->cache_dir, &fst) < 0) {
			mkdir_with_parents(client->cache_dir, 0755);
		}
		strcpy(version_xml, client->cache_dir);
		strcat(version_xml, "/");
		strcat(version_xml, VERSION_XML);
	} else {
		strcpy(version_xml, VERSION_XML);
	}

	if ((stat(version_xml, &fst) < 0) || ((time(NULL)-86400) > fst.st_mtime)) {
		char version_xml_tmp[1024];
		strcpy(version_xml_tmp, version_xml);
		strcat(version_xml_tmp, ".tmp");

		if (download_to_file("http://itunes.apple.com/check/version",  version_xml_tmp, 0) == 0) {
			remove(version_xml);
			if (rename(version_xml_tmp, version_xml) < 0) {
				logger(LL_ERROR, "Could not update '%s'\n", version_xml);
			} else {
				logger(LL_INFO, "Updated version data.\n");
			}
		}
	} else {
		cached = 1;
	}

	char *verbuf = NULL;
	size_t verlen = 0;
	read_file(version_xml, (void**)&verbuf, &verlen);

	if (!verbuf) {
		logger(LL_ERROR, "Could not load '%s'\n", version_xml);
		return -1;
	}

	client->version_data = NULL;
	plist_from_xml(verbuf, verlen, &client->version_data);
	free(verbuf);

	if (!client->version_data) {
		remove(version_xml);
		logger(LL_ERROR, "Cannot parse plist data from '%s'.\n", version_xml);
		return -1;
	}

	if (cached) {
		logger(LL_INFO, "Using cached version data\n");
	}

	return 0;
}

static int32_t get_version_num(const char *s_ver)
{
        int vers[3] = {0, 0, 0};
        if (sscanf(s_ver, "%d.%d.%d", &vers[0], &vers[1], &vers[2]) >= 2) {
                return ((vers[0] & 0xFF) << 16) | ((vers[1] & 0xFF) << 8) | (vers[2] & 0xFF);
        }
        return 0x00FFFFFF;
}

static int compare_versions(const char *s_ver1, const char *s_ver2)
{
	return (get_version_num(s_ver1) & 0xFFFF00) - (get_version_num(s_ver2) & 0xFFFF00);
}

static void idevice_event_cb(const idevice_event_t *event, void *userdata)
{
	struct idevicerestore_client_t *client = (struct idevicerestore_client_t*)userdata;
#ifdef HAVE_ENUM_IDEVICE_CONNECTION_TYPE
	if (event->conn_type != CONNECTION_USBMUXD) {
		// ignore everything but devices connected through USB
		return;
	}
#endif
	if (event->event == IDEVICE_DEVICE_ADD) {
		if (client->ignore_device_add_events) {
			return;
		}
		if (normal_check_mode(client) == 0) {
			mutex_lock(&client->device_event_mutex);
			client->mode = MODE_NORMAL;
			logger(LL_DEBUG, "%s: device %016" PRIx64 " (udid: %s) connected in normal mode\n", __func__, client->ecid, client->udid);
			cond_signal(&client->device_event_cond);
			mutex_unlock(&client->device_event_mutex);
		} else if (client->ecid && restore_check_mode(client) == 0) {
			mutex_lock(&client->device_event_mutex);
			client->mode = MODE_RESTORE;
			logger(LL_DEBUG, "%s: device %016" PRIx64 " (udid: %s) connected in restore mode\n", __func__, client->ecid, client->udid);
			cond_signal(&client->device_event_cond);
			mutex_unlock(&client->device_event_mutex);
		}
		if (!client->device) {
			client->device = get_irecv_device(client);
		}
	} else if (event->event == IDEVICE_DEVICE_REMOVE) {
		if (client->udid && !strcmp(event->udid, client->udid)) {
			mutex_lock(&client->device_event_mutex);
			client->mode = MODE_UNKNOWN;
			logger(LL_DEBUG, "%s: device %016" PRIx64 " (udid: %s) disconnected\n", __func__, client->ecid, client->udid);
			client->ignore_device_add_events = 0;
			cond_signal(&client->device_event_cond);
			mutex_unlock(&client->device_event_mutex);
		}
	}
}

static void irecv_event_cb(const irecv_device_event_t* event, void *userdata)
{
	struct idevicerestore_client_t *client = (struct idevicerestore_client_t*)userdata;
	if (event->type == IRECV_DEVICE_ADD) {
		if (!client->udid && !client->ecid) {
			client->ecid = event->device_info->ecid;
		}
		if (client->ecid && event->device_info->ecid == client->ecid) {
			mutex_lock(&client->device_event_mutex);
			switch (event->mode) {
				case IRECV_K_WTF_MODE:
					client->mode = MODE_WTF;
					break;
				case IRECV_K_DFU_MODE:
					client->mode = MODE_DFU;
					break;
				case IRECV_K_PORT_DFU_MODE:
					client->mode = MODE_PORTDFU;
					break;
#ifdef HAVE_TURDUS_MERULA
				case IRECV_K_PONGO_MODE:
					client->mode = MODE_PONGO;
					break;
#endif
				case IRECV_K_RECOVERY_MODE_1:
				case IRECV_K_RECOVERY_MODE_2:
				case IRECV_K_RECOVERY_MODE_3:
				case IRECV_K_RECOVERY_MODE_4:
					client->mode = MODE_RECOVERY;
					break;
				default:
					client->mode = MODE_UNKNOWN;
			}
			logger(LL_DEBUG, "%s: device %016" PRIx64 " (udid: %s) connected in %s mode\n", __func__, client->ecid, (client->udid) ? client->udid : "N/A", client->mode->string);
			if (!client->device) {
				client->device = get_irecv_device(client);
			}
			cond_signal(&client->device_event_cond);
			mutex_unlock(&client->device_event_mutex);
		}
	} else if (event->type == IRECV_DEVICE_REMOVE) {
		if (client->ecid && event->device_info->ecid == client->ecid) {
			mutex_lock(&client->device_event_mutex);
			client->mode = MODE_UNKNOWN;
			logger(LL_DEBUG, "%s: device %016" PRIx64 " (udid: %s) disconnected\n", __func__, client->ecid, (client->udid) ? client->udid : "N/A");
			if (event->mode == IRECV_K_PORT_DFU_MODE) {
				// We have to reset the ECID here if a port DFU device disconnects,
				// because when the device reconnects in a different mode, it will
				// have the actual device ECID and wouldn't get detected.
				client->ecid = 0;
			}
			cond_signal(&client->device_event_cond);
			mutex_unlock(&client->device_event_mutex);
		}
	}
}

int build_identity_check_components_in_ipsw(plist_t build_identity, ipsw_archive_t ipsw);

int idevicerestore_start(struct idevicerestore_client_t* client)
{
	int tss_enabled = 0;
	int result = 0;

	if (!client) {
		return -1;
	}

	if ((client->flags & FLAG_LATEST) && (client->flags & FLAG_CUSTOM)) {
		logger(LL_ERROR, "FLAG_LATEST cannot be used with FLAG_CUSTOM.\n");
		return -1;
	}

	if (!client->ipsw && !(client->flags & FLAG_PWN) && !(client->flags & FLAG_LATEST)) {
		logger(LL_ERROR, "no ipsw file given\n");
		return -1;
	}

	if (client->debug_level > 0) {
		idevicerestore_debug = 1;
		if (client->debug_level > 1) {
			irecv_set_debug_level(1);
		}
		if (client->debug_level > 2) {
			idevice_set_debug_level(1);
		}
		tss_set_debug_level(client->debug_level);
	}

	progress_reset_tag();

	idevicerestore_progress(client, RESTORE_STEP_DETECT, 0.0);

	if (!client->irecv_e_ctx) {
		irecv_device_event_subscribe(&client->irecv_e_ctx, irecv_event_cb, client);
	}

	if (!client->idevice_e_ctx) {
		idevice_event_subscribe(idevice_event_cb, client);
		client->idevice_e_ctx = idevice_event_cb;
	}

	// check which mode the device is currently in so we know where to start
	mutex_lock(&client->device_event_mutex);
	if (
		client->mode == MODE_UNKNOWN
#ifdef HAVE_TURDUS_MERULA
		|| ((client->flags & FLAG_DOWNGRADE) && client->mode->index != _MODE_DFU && client->mode->index != _MODE_RECOVERY)
#endif
		)
	{
		cond_wait_timeout(&client->device_event_cond, &client->device_event_mutex, 10000);
		if (client->mode == MODE_UNKNOWN || (client->flags & FLAG_QUIT)) {
			mutex_unlock(&client->device_event_mutex);
			logger(LL_ERROR, "Unable to discover device mode. Please make sure a device is attached.\n");
			return -1;
		}
	}
	idevicerestore_progress(client, RESTORE_STEP_DETECT, 0.1);
	logger(LL_INFO, "Found device in %s mode\n", client->mode->string);
	mutex_unlock(&client->device_event_mutex);

	if (client->mode == MODE_WTF) {
		unsigned int cpid = 0;

		if (dfu_client_new(client) != 0) {
			logger(LL_ERROR, "Could not open device in WTF mode\n");
			return -1;
		}
		if ((dfu_get_cpid(client, &cpid) < 0) || (cpid == 0)) {
			logger(LL_ERROR, "Could not get CPID for WTF mode device\n");
			dfu_client_free(client);
			return -1;
		}

		char wtfname[256];
		snprintf(wtfname, sizeof(wtfname), "Firmware/dfu/WTF.s5l%04xxall.RELEASE.dfu", cpid);
		void* wtftmp = NULL;
		size_t wtfsize = 0;

		// Prefer to get WTF file from the restore IPSW
		ipsw_extract_to_memory(client->ipsw, wtfname, &wtftmp, &wtfsize);
		if (!wtftmp) {
			// update version data (from cache, or apple if too old)
			load_version_data(client);

			// Download WTF IPSW
			char* s_wtfurl = NULL;
			plist_t wtfurl = plist_access_path(client->version_data, 7, "MobileDeviceSoftwareVersionsByVersion", "5", "RecoverySoftwareVersions", "WTF", "304218112", "5", "FirmwareURL");
			if (wtfurl && (plist_get_node_type(wtfurl) == PLIST_STRING)) {
				plist_get_string_val(wtfurl, &s_wtfurl);
			}
			if (!s_wtfurl) {
				logger(LL_INFO, "Using hardcoded x12220000_5_Recovery.ipsw URL\n");
				s_wtfurl = strdup("http://appldnld.apple.com.edgesuite.net/content.info.apple.com/iPhone/061-6618.20090617.Xse7Y/x12220000_5_Recovery.ipsw");
			}

			// make a local file name
			char* fnpart = strrchr(s_wtfurl, '/');
			if (!fnpart) {
				fnpart = (char*)"x12220000_5_Recovery.ipsw";
			} else {
				fnpart++;
			}
			struct stat fst;
			char wtfipsw[1024];
			if (client->cache_dir) {
				if (stat(client->cache_dir, &fst) < 0) {
					mkdir_with_parents(client->cache_dir, 0755);
				}
				strcpy(wtfipsw, client->cache_dir);
				strcat(wtfipsw, "/");
				strcat(wtfipsw, fnpart);
			} else {
				strcpy(wtfipsw, fnpart);
			}
			if (stat(wtfipsw, &fst) != 0) {
				download_to_file(s_wtfurl, wtfipsw, 0);
			}

			ipsw_archive_t wtf_ipsw = ipsw_open(wtfipsw);
			ipsw_extract_to_memory(wtf_ipsw, wtfname, &wtftmp, &wtfsize);
			ipsw_close(wtf_ipsw);
			if (!wtftmp) {
				logger(LL_ERROR, "Could not extract WTF\n");
			}
		}

		mutex_lock(&client->device_event_mutex);
		if (wtftmp) {
			if (dfu_send_buffer(client, wtftmp, wtfsize) != 0) {
				logger(LL_ERROR, "Could not send WTF...\n");
			}
		}
		dfu_client_free(client);

		free(wtftmp);

		cond_wait_timeout(&client->device_event_cond, &client->device_event_mutex, 10000);
		if (client->mode != MODE_DFU || (client->flags & FLAG_QUIT)) {
			mutex_unlock(&client->device_event_mutex);
			/* TODO: verify if it actually goes from 0x1222 -> 0x1227 */
			logger(LL_ERROR, "Failed to put device into DFU from WTF mode\n");
			return -1;
		}
		mutex_unlock(&client->device_event_mutex);
	}

	// discover the device type
	client->device = get_irecv_device(client);
	if (client->device == NULL) {
		logger(LL_ERROR, "Unable to discover device type\n");
		return -1;
	}
	if (client->ecid == 0) {
		logger(LL_ERROR, "Unable to determine ECID\n");
		return -1;
	}
	logger(LL_INFO, "ECID: %" PRIu64 "\n", client->ecid);

	idevicerestore_progress(client, RESTORE_STEP_DETECT, 0.2);
	logger(LL_INFO, "Identified device as %s, %s\n", client->device->hardware_model, client->device->product_type);

	if ((client->flags & FLAG_PWN) && (client->mode != MODE_DFU)) {
		logger(LL_ERROR, "you need to put your device into DFU mode to pwn it.\n");
		return -1;
	}

#ifdef HAVE_TURDUS_MERULA
	if (client->flags & FLAG_DOWNGRADE) {
		if (client->mode != MODE_DFU) { // check pwnd DFU
			logger(LL_ERROR, "You need to put your device into pwned DFU mode to use downgrade mode.\n");
			return -1;
		}
		int not_pwnd = dfu_get_pwned_dfu(client);
		if (not_pwnd) {
			logger(LL_ERROR, "You need to put your device into pwned DFU mode.\n");
			return -1;
		}
		
		if (
			(client->flags & FLAG_CUSTOM) ||
			(client->flags & FLAG_EXCLUDE) ||
			(client->flags & FLAG_PWN) ||
			(client->flags & FLAG_SHSHONLY) ||
			(client->flags & FLAG_LATEST) ||
			(client->flags & FLAG_ALLOW_RESTORE_MODE) ||
			(client->flags & FLAG_NO_RESTORE)
			)
		{
			logger(LL_ERROR, "Client flags contains a value that is not available in downgrade mode.\n");
			return -2;
		}
		
		// get cpid
		unsigned int cpid = 0;
		unsigned int bdid = 0;
		if (dfu_get_cpid(client, &cpid)) {
			logger(LL_ERROR, "Unable to fetch CPID\n");
			return -2;
		}
		if (dfu_get_bdid(client, &bdid)) {
			logger(LL_ERROR, "Unable to fetch BDID\n");
			return -2;
		}
		client->cpid = cpid;
		client->bdid = bdid;
		
		// check device
		if (is_a10_variant_soc(client->cpid)) {
			if (client->flags & (FLAG_FETCH_BSEP | FLAG_LOAD_BSEP)) {
				logger(LL_ERROR, "bsep is not supported in this SoC\n");
				return -2;
			}
		}
		else if (is_a9_variant_soc(client->cpid)) {
			if ((client->flags & FLAG_LOAD_BSEP_SHC) && (client->flags & FLAG_LOAD_BSEP_PTE)) {
				logger(LL_ERROR, "Conflict detected\n");
				return -2;
			}
			if ((client->flags & FLAG_FETCH_BSEP_SHC) && (client->flags & FLAG_FETCH_BSEP_PTE)) {
				logger(LL_ERROR, "Conflict detected\n");
				return -2;
			}
			if ((client->flags & FLAG_FETCH_BSEP_PTE) && (client->flags & FLAG_LOAD_BSEP_PTE)) {
				logger(LL_ERROR, "Conflict detected\n");
				return -2;
			}
			if (!(client->flags & FLAG_CHECK_A9)) {
				logger(LL_ERROR, "No exploit method selected\n");
				return -2;
			}
		}
		else if (is_a8_variant_soc(client->cpid)) {
			if ((client->flags & FLAG_LOAD_BSEP_SHC) && (client->flags & FLAG_LOAD_BSEP_PTE)) {
				logger(LL_ERROR, "Conflict detected\n");
				return -2;
			}
			if ((client->flags & FLAG_FETCH_BSEP_SHC) && (client->flags & FLAG_FETCH_BSEP_PTE)) {
				logger(LL_ERROR, "Conflict detected\n");
				return -2;
			}
			if ((client->flags & FLAG_FETCH_BSEP_PTE) && (client->flags & FLAG_LOAD_BSEP_PTE)) {
				logger(LL_ERROR, "Conflict detected\n");
				return -2;
			}
			if (!(client->flags & FLAG_CHECK_A8)) {
				logger(LL_ERROR, "No exploit method selected\n");
				return -2;
			}
		}
		else if (is_armv7s_soc(client->cpid)) {
			if (client->flags & (FLAG_FETCH_BSEP | FLAG_LOAD_BSEP)) {
				logger(LL_ERROR, "This device does not support SEP/PongoOS.\n");
				return -2;
			}
		}
		else {
			logger(LL_ERROR, "Unsupported device (CPID: %04x)\n", client->cpid);
			return -2;
		}
		
		// check shsh
		// some modes require fetching from the server, so don't check them yet
		if (
			!(client->flags & FLAG_TETHERED) && // !tethered
			!(client->flags & FLAG_FETCH_BSEP)  // !pongoonly
			)
		{
			if (!client->use_custom_ticket || !ap_shsh_path) {
				logger(LL_ERROR, "local shsh not selected\n");
				return -2;
			}
			
			logger(LL_DEBUG, "reading for local shsh\n");
			char zfn[1024];
			snprintf(zfn, sizeof(zfn), "%s", ap_shsh_path);
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
							plist_from_bin(bin, blen, &client->local_shsh);
						}
						else {
							plist_from_xml(bin, blen, &client->local_shsh);
						}
					}
					free(bin);
				}
			}
			else {
				logger(LL_ERROR, "no local file %s\n", zfn);
				return -1;
			}
		}
	}
#endif

	if (client->mode == MODE_NORMAL) {
		plist_t pver = normal_get_lockdown_value(client, NULL, "ProductVersion");
		if (pver) {
			plist_get_string_val(pver, &client->device_version);
			plist_free(pver);
		}
		pver = normal_get_lockdown_value(client, NULL, "BuildVersion");
		if (pver) {
			plist_get_string_val(pver, &client->device_build);
			plist_free(pver);
		}
	}
	logger(LL_INFO, "Device Product Version: %s\n", (client->device_version) ? client->device_version : "N/A");
	logger(LL_INFO, "Device Product Build: %s\n", (client->device_build) ? client->device_build : "N/A");

	if (client->flags & FLAG_PWN) {
#ifdef HAVE_LIMERA1N
		recovery_client_free(client);

		if (client->mode != MODE_DFU) {
			logger(LL_ERROR, "Device needs to be in DFU mode for this option.\n");
			return -1;
		}

		logger(LL_INFO, "connecting to DFU\n");
		if (dfu_client_new(client) < 0) {
			return -1;
		}

		if (limera1n_is_supported(client->device)) {
			logger(LL_INFO, "exploiting with limera1n...\n");
			if (limera1n_exploit(client->device, &client->dfu->client) != 0) {
				logger(LL_ERROR, "limera1n exploit failed\n");
				dfu_client_free(client);
				return -1;
			}
			dfu_client_free(client);
			logger(LL_INFO, "Device should be in pwned DFU state now.\n");

			return 0;
		}
		else {
			dfu_client_free(client);
			logger(LL_ERROR, "This device is not supported by the limera1n exploit");
			return -1;
		}
#endif
	}

	if (client->flags & FLAG_LATEST) {
		char *fwurl = NULL;
		unsigned char fwsha1[20];
		unsigned char *p_fwsha1 = NULL;
		plist_t signed_fws = NULL;
		int res = ipsw_get_signed_firmwares(client->device->product_type, &signed_fws);
		if (res < 0) {
			logger(LL_ERROR, "Could not fetch list of signed firmwares.\n");
			return res;
		}
		uint32_t count = plist_array_get_size(signed_fws);
		if (count == 0) {
			plist_free(signed_fws);
			logger(LL_ERROR, "No firmwares are currently being signed for %s (REALLY?!)\n", client->device->product_type);
			return -1;
		}
		plist_t selected_fw = NULL;
		if (client->flags & FLAG_INTERACTIVE) {
			uint32_t i = 0;
			logger(LL_INFO, "The following firmwares are currently being signed for %s:\n", client->device->product_type);
			for (i = 0; i < count; i++) {
				plist_t fw = plist_array_get_item(signed_fws, i);
				plist_t p_version = plist_dict_get_item(fw, "version");
				plist_t p_build = plist_dict_get_item(fw, "buildid");
				logger(LL_INFO, "  [%d] %s (build %s)\n", i+1, plist_get_string_ptr(p_version, NULL), plist_get_string_ptr(p_build, NULL));
			}
			while (1) {
				char input[64];
				printf("Select the firmware you want to restore: ");
				fflush(stdout);
				fflush(stdin);
				get_user_input(input, 63, 0);
				if (*input == '\0') {
					plist_free(signed_fws);
					return -1;
				}
				if (client->flags & FLAG_QUIT) {
					return -1;
				}
				unsigned long selected = strtoul(input, NULL, 10);
				if (selected == 0 || selected > count) {
					printf("Invalid input value. Must be in range: 1..%u\n", count);
					continue;
				}
				selected_fw = plist_array_get_item(signed_fws, (uint32_t)selected-1);
				break;
			}
		} else {
			logger(LL_NOTICE, "Running non-interactively, automatically selecting latest available version\n");
			selected_fw = plist_array_get_item(signed_fws, 0);
		}
		if (!selected_fw) {
			logger(LL_ERROR, "failed to select latest firmware?!\n");
			plist_free(signed_fws);
			return -1;
		} else {
			plist_t p_version = plist_dict_get_item(selected_fw, "version");
			plist_t p_build = plist_dict_get_item(selected_fw, "buildid");
			logger(LL_NOTICE, "Selected firmware %s (build %s)\n", plist_get_string_ptr(p_version, NULL), plist_get_string_ptr(p_build, NULL));
			plist_t p_url = plist_dict_get_item(selected_fw, "url");
			plist_t p_sha1 = plist_dict_get_item(selected_fw, "sha1sum");
			char *s_sha1 = NULL;
			plist_get_string_val(p_url, &fwurl);
			plist_get_string_val(p_sha1, &s_sha1);
			if (strlen(s_sha1) == 40) {
				int i;
				int v;
				for (i = 0; i < 40; i+=2) {
					v = 0;
					sscanf(s_sha1+i, "%02x", &v);
					fwsha1[i/2] = (unsigned char)v;
				}
				p_fwsha1 = &fwsha1[0];
			} else {
				logger(LL_ERROR, "unexpected size of sha1sum\n");
			}
		}
		plist_free(signed_fws);

		if (!fwurl || !p_fwsha1) {
			logger(LL_ERROR, "Missing firmware URL or SHA1\n");
			return -1;
		}

		char* ipsw = NULL;
		res = ipsw_download_fw(fwurl, p_fwsha1, client->cache_dir, &ipsw);
		if (res != 0) {
			free(ipsw);
			return res;
		} else {
			client->ipsw = ipsw_open(ipsw);
			if (!client->ipsw) {
				logger(LL_ERROR, "Failed to open ipsw '%s'\n", ipsw);
				free(ipsw);
				return -1;
			}
			free(ipsw);
		}
	}
	idevicerestore_progress(client, RESTORE_STEP_DETECT, 0.6);

	if (client->flags & FLAG_NOACTION) {
		return 0;
	}

	// extract buildmanifest
	if (client->flags & FLAG_CUSTOM) {
		logger(LL_INFO, "Extracting Restore.plist from IPSW\n");
		if (ipsw_extract_restore_plist(client->ipsw, &client->build_manifest) < 0) {
			logger(LL_ERROR, "Unable to extract Restore.plist from %s. Firmware file might be corrupt.\n", client->ipsw->path);
			return -1;
		}
	} else {
		logger(LL_INFO, "Extracting BuildManifest from IPSW\n");
		if (ipsw_extract_build_manifest(client->ipsw, &client->build_manifest, &tss_enabled) < 0) {
			logger(LL_ERROR, "Unable to extract BuildManifest from %s. Firmware file might be corrupt.\n", client->ipsw->path);
			return -1;
		}
	}

	if (client->flags & FLAG_CUSTOM) {
		// prevent attempt to sign custom firmware
		tss_enabled = 0;
		logger(LL_INFO, "Custom firmware requested; TSS has been disabled.\n");
	}

	if (client->mode == MODE_RESTORE) {
		if (!(client->flags & FLAG_ALLOW_RESTORE_MODE)) {
			if (restore_reboot(client) < 0) {
				logger(LL_ERROR, "Unable to exit restore mode\n");
				return -2;
			}

			// we need to refresh the current mode again
			mutex_lock(&client->device_event_mutex);
			cond_wait_timeout(&client->device_event_cond, &client->device_event_mutex, 60000);
			if (client->mode == MODE_UNKNOWN || (client->flags & FLAG_QUIT)) {
				mutex_unlock(&client->device_event_mutex);
				logger(LL_ERROR, "Unable to discover device mode. Please make sure a device is attached.\n");
				return -1;
			}
			logger(LL_INFO, "Found device in %s mode\n", client->mode->string);
			mutex_unlock(&client->device_event_mutex);
		}
	}

	if (client->mode == MODE_PORTDFU) {
		unsigned int pdfu_bdid = 0;
		unsigned int pdfu_cpid = 0;
		unsigned int prev = 0;

		if (dfu_get_bdid(client, &pdfu_bdid) < 0) {
			logger(LL_ERROR, "Failed to get bdid for Port DFU device!\n");
			return -1;
		}
		if (dfu_get_cpid(client, &pdfu_cpid) < 0) {
			logger(LL_ERROR, "Failed to get cpid for Port DFU device!\n");
			return -1;
		}
		if (dfu_get_prev(client, &prev) < 0) {
			logger(LL_ERROR, "Failed to get PREV for Port DFU device!\n");
			return -1;
		}

		unsigned char* pdfu_nonce = NULL;
		unsigned int pdfu_nsize = 0;
		if (dfu_get_portdfu_nonce(client, &pdfu_nonce, &pdfu_nsize) < 0) {
			logger(LL_ERROR, "Failed to get nonce for Port DFU device!\n");
			return -1;
		}

		plist_t build_identity = build_manifest_get_build_identity_for_model_with_variant(client->build_manifest, client->device->hardware_model, RESTORE_VARIANT_ERASE_INSTALL, 0);
		if (!build_identity) {
			logger(LL_ERROR, "ERORR: Failed to get build identity\n");
			return -1;
		}

		unsigned int b_pdfu_cpid = (unsigned int)plist_dict_get_uint(build_identity, "USBPortController1,ChipID");
		if (b_pdfu_cpid != pdfu_cpid) {
			logger(LL_ERROR, "cpid 0x%02x doesn't match USBPortController1,ChipID in build identity (0x%02x)\n", pdfu_cpid, b_pdfu_cpid);
			return -1;
		}
		unsigned int b_pdfu_bdid = (unsigned int)plist_dict_get_uint(build_identity, "USBPortController1,BoardID");
		if (b_pdfu_bdid != pdfu_bdid) {
			logger(LL_ERROR, "bdid 0x%x doesn't match USBPortController1,BoardID in build identity (0x%x)\n", pdfu_bdid, b_pdfu_bdid);
			return -1;
		}

		plist_t parameters = plist_new_dict();
		plist_dict_set_item(parameters, "@USBPortController1,Ticket", plist_new_bool(1));
		plist_dict_set_item(parameters, "USBPortController1,ECID", plist_new_int(client->ecid));
		plist_dict_copy_item(parameters, build_identity, "USBPortController1,BoardID", NULL);
		plist_dict_copy_item(parameters, build_identity, "USBPortController1,ChipID", NULL);
		plist_dict_copy_item(parameters, build_identity, "USBPortController1,SecurityDomain", NULL);
		plist_dict_set_item(parameters, "USBPortController1,SecurityMode", plist_new_bool(1));
		plist_dict_set_item(parameters, "USBPortController1,ProductionMode", plist_new_bool(1));
		int is_mac = plist_access_path(build_identity, 2, "Info", "MacOSVariant") != NULL;
		plist_t usbf = plist_access_path(build_identity, 2, "Manifest", "USBPortController1,USBFirmware");
		if (!usbf) {
			plist_free(parameters);
			logger(LL_ERROR, "Unable to find USBPortController1,USBFirmware in build identity\n");
			return -1;
		}
		plist_t p_fwpath = plist_access_path(usbf, 2, "Info", "Path");
		if (!p_fwpath) {
			plist_free(parameters);
			logger(LL_ERROR, "Unable to find path of USBPortController1,USBFirmware component\n");
			return -1;
		}
		const char* fwpath = plist_get_string_ptr(p_fwpath, NULL);
		if (!fwpath) {
			plist_free(parameters);
			logger(LL_ERROR, "Unable to get path of USBPortController1,USBFirmware component\n");
			return -1;
		}
		void* uarp_buf = NULL;
		size_t uarp_size = 0;
		if (ipsw_extract_to_memory(client->ipsw, fwpath, &uarp_buf, &uarp_size) < 0) {
			plist_free(parameters);
			logger(LL_ERROR, "Unable to extract '%s' from IPSW\n", fwpath);
			return -1;
		}
		usbf = plist_copy(usbf);
		plist_dict_remove_item(usbf, "Info");
		plist_dict_set_item(parameters, "USBPortController1,USBFirmware", usbf);
		plist_dict_set_item(parameters, "USBPortController1,Nonce", plist_new_data((const char*)pdfu_nonce, pdfu_nsize));

		plist_t request = tss_request_new(NULL);
		if (request == NULL) {
			plist_free(parameters);
			logger(LL_ERROR, "Unable to create TSS request\n");
			return -1;
		}
		plist_dict_merge(&request, parameters);
		plist_free(parameters);

		// send request and grab response
		plist_t response = tss_request_send(request, client->tss_url);
		plist_free(request);
		if (response == NULL) {
			logger(LL_ERROR, "Unable to send TSS request\n");
			return -1;
		}
		logger(LL_INFO, "Received USBPortController1,Ticket\n");

		logger(LL_INFO, "Creating Ace3Binary\n");
		void* ace3bin = NULL;
		size_t ace3bin_size = 0;
		if (ace3_create_binary(uarp_buf, uarp_size, pdfu_bdid, prev, response, &ace3bin, &ace3bin_size) < 0) {
			logger(LL_ERROR, "Could not create Ace3Binary\n");
			return -1;
		}
		plist_free(response);
		free(uarp_buf);

		if (client->flags & FLAG_KEEP_PERS) {
			write_file("Ace3Binary", ace3bin, ace3bin_size);
		}

		if (dfu_send_buffer_with_options(client, ace3bin, ace3bin_size, IRECV_SEND_OPT_DFU_NOTIFY_FINISH | IRECV_SEND_OPT_DFU_SMALL_PKT) < 0) {
			logger(LL_ERROR, "Could not send Ace3Buffer to device\n");
			return -1;
		}

		logger(LL_DEBUG, "Waiting for device to disconnect...\n");
		cond_wait_timeout(&client->device_event_cond, &client->device_event_mutex, 5000);
		if (client->mode != MODE_UNKNOWN || (client->flags & FLAG_QUIT)) {
			mutex_unlock(&client->device_event_mutex);

			if (!(client->flags & FLAG_QUIT)) {
				logger(LL_ERROR, "Device did not disconnect. Port DFU failed.\n");
			}
			return -2;
		}
		dfu_client_free(client);
		logger(LL_DEBUG, "Waiting for device to reconnect in DFU mode...\n");
		cond_wait_timeout(&client->device_event_cond, &client->device_event_mutex, 20000);
		if (client->mode != MODE_DFU || (client->flags & FLAG_QUIT)) {
			mutex_unlock(&client->device_event_mutex);
			if (!(client->flags & FLAG_QUIT)) {
				logger(LL_ERROR, "Device did not reconnect in DFU mode. Port DFU failed.\n");
				if (is_mac) {
					logger(LL_ERROR, "Make sure to use the correct USB port for this model, see https://support.apple.com/120694\n");
				}
			}
			return -2;
		}
		mutex_unlock(&client->device_event_mutex);

		if (client->flags & FLAG_NOACTION) {
			logger(LL_INFO, "Port DFU restore successful.\n");
			return 0;
		} else {
			logger(LL_INFO, "Port DFU restore successful. Continuing.\n");
		}
	}

	idevicerestore_progress(client, RESTORE_STEP_DETECT, 0.8);

	/* check if device type is supported by the given build manifest */
	if (build_manifest_check_compatibility(client->build_manifest, client->device->product_type) < 0) {
		logger(LL_ERROR, "Could not make sure this firmware is suitable for the current device. Refusing to continue.\n");
		return -1;
	}

	/* print iOS information from the manifest */
	build_manifest_get_version_information(client->build_manifest, client);

	logger(LL_INFO, "IPSW Product Version: %s\n", client->version);
	logger(LL_INFO, "IPSW Product Build: %s Major: %d\n", client->build, client->build_major);

#ifdef HAVE_TURDUS_MERULA
	// check RAMDisk type
#define RDSK_TYPE_NONE          (0)
#define RDSK_TYPE_UNION_IOS     (1u << 0)
#define RDSK_TYPE_UNION_TVOS    (1u << 1)
#define RDSK_TYPE_DYLDHOOK_IOS  (1u << 2)
#define RDSK_TYPE_DYLDHOOK_TVOS (1u << 3)
	if (client->flags & FLAG_DOWNGRADE) {
		if (is_arm64_soc(client->cpid)) {
			uint32_t rdsk_type = RDSK_TYPE_NONE;
			{
				int is_tvos = is_tvos_with_cpid_bdid(client->cpid, client->bdid);
				if (client->build_major >= 14) {
					if (client->build_major == 14 || client->build_major == 15) {
						if (is_tvos == 0) { // iPhoneOS
							rdsk_type |= RDSK_TYPE_UNION_IOS;
						}
						if (is_tvos == 1) { // tvOS
							rdsk_type |= RDSK_TYPE_UNION_TVOS;
						}
					}
					else {
						if (is_tvos == 0) { // iPhoneOS
							rdsk_type |= RDSK_TYPE_DYLDHOOK_IOS;
						}
						if (is_tvos == 1) { // tvOS
							rdsk_type |= RDSK_TYPE_DYLDHOOK_TVOS;
						}
					}
				}
			}
			logger(LL_INFO, "RAMDisk type: 0x%04x\n", rdsk_type);
			
			// load RAMDisk
			if (rdsk_type != 0) {
				if (gRAMDisk == NULL) {
					logger(LL_INFO, "Loading overlay ramdisk...\n");
					unsigned int ramdisk_length = 0;
					void* ramdisk_buffer = NULL;
					if (rdsk_type & RDSK_TYPE_UNION_IOS) {
						ramdisk_buffer = union_iphoneos_bin;
						ramdisk_length = union_iphoneos_bin_len;
					}
					else if (rdsk_type & RDSK_TYPE_UNION_TVOS) {
						ramdisk_buffer = union_tvos_bin;
						ramdisk_length = union_tvos_bin_len;
					}
					else if (rdsk_type & RDSK_TYPE_DYLDHOOK_IOS) {
						ramdisk_buffer = overlay_iphoneos_bin;
						ramdisk_length = overlay_iphoneos_bin_len;
					}
					else if (rdsk_type & RDSK_TYPE_DYLDHOOK_TVOS) {
						ramdisk_buffer = overlay_tvos_bin;
						ramdisk_length = overlay_tvos_bin_len;
					}
					else {
						logger(LL_ERROR, "Invalid rdsk_type\n");
						return -1;
					}
					void* tmp_buffer = NULL;
					int res = posix_memalign(&tmp_buffer, sizeof(uint64_t), ramdisk_length);
					if (res != 0) {
						logger(LL_ERROR, "memalign failed (reason: %s)", strerror(res));
						return -1;
					}
					if (tmp_buffer == NULL) {
						logger(LL_ERROR, "Out of memory\n");
						return -1;
					}
					memcpy(tmp_buffer, ramdisk_buffer, ramdisk_length);
					gRAMDisk = tmp_buffer;
					gRAMDiskLength = ramdisk_length;
					logger(LL_INFO, "Loaded embedded overlay ramdisk, length %zu\n", gRAMDiskLength);
				}
			}
			
			// load module and pongo
			if (gPongoOS == NULL) {
				logger(LL_INFO, "Loading Pongo...\n");
				void* tmp_buffer = NULL;
				int res = posix_memalign(&tmp_buffer, sizeof(uint64_t), Pongo_bin_len);
				if (res != 0) {
					logger(LL_ERROR, "memalign failed (reason: %s)", strerror(res));
					return -1;
				}
				if (tmp_buffer == NULL) {
					logger(LL_ERROR, "Out of memory\n");
					return -1;
				}
				memcpy(tmp_buffer, Pongo_bin, Pongo_bin_len);
				gPongoOS = tmp_buffer;
				gPongoOSLength = Pongo_bin_len;
				logger(LL_INFO, "Loaded embedded Pongo, length %zu\n", gPongoOSLength);
			}
			if (gSEPRacer == NULL) {
				logger(LL_INFO, "Loading sep_racer...\n");
				void* tmp_buffer = NULL;
				int res = posix_memalign(&tmp_buffer, sizeof(uint64_t), sep_racer_bin_len);
				if (res != 0) {
					logger(LL_ERROR, "memalign failed (reason: %s)", strerror(res));
					return -1;
				}
				if (tmp_buffer == NULL) {
					logger(LL_ERROR, "Out of memory\n");
					return -1;
				}
				memcpy(tmp_buffer, sep_racer_bin, sep_racer_bin_len);
				gSEPRacer = tmp_buffer;
				gSEPRacerLength = sep_racer_bin_len;
				logger(LL_INFO, "Loaded embedded sep_racer module, length %zu\n", gSEPRacerLength);
			}
			if (gKPF == NULL) {
				logger(LL_INFO, "Loading kpf...\n");
				void* tmp_buffer = NULL;
				int res = posix_memalign(&tmp_buffer, sizeof(uint64_t), kpf_bin_len);
				if (res != 0) {
					logger(LL_ERROR, "memalign failed (reason: %s)", strerror(res));
					return -1;
				}
				if (tmp_buffer == NULL) {
					logger(LL_ERROR, "Out of memory\n");
					return -1;
				}
				memcpy(tmp_buffer, kpf_bin, kpf_bin_len);
				gKPF = tmp_buffer;
				gKPFLength = kpf_bin_len;
				logger(LL_INFO, "Loaded embedded kpf module, length %zu\n", gKPFLength);
			}
			if (gCPF == NULL) {
				logger(LL_INFO, "Loading cpf...\n");
				void* tmp_buffer = NULL;
				int res = posix_memalign(&tmp_buffer, sizeof(uint64_t), cpf_bin_len);
				if (res != 0) {
					logger(LL_ERROR, "memalign failed (reason: %s)", strerror(res));
					return -1;
				}
				if (tmp_buffer == NULL) {
					logger(LL_ERROR, "Out of memory\n");
					return -1;
				}
				memcpy(tmp_buffer, cpf_bin, cpf_bin_len);
				gCPF = tmp_buffer;
				gCPFLength = cpf_bin_len;
				logger(LL_INFO, "Loaded embedded cpf module, length %zu\n", gCPFLength);
			}
			
			// check pongo
			{
				logger(LL_INFO, "Checking Pongo image...\n");
				int found = 0;
				const uint64_t magicval = PONGO_MAGIC_VALUE; // 0x1337cafebabe4100uLL
				uint8_t* cur = gPongoOS;
				const uint8_t* end = (uint8_t*)(cur + gPongoOSLength - sizeof(uint64_t));
				while (cur <= end) {
					if (read_u64_le(cur) == magicval) {
						found = 1;
						break;
					}
					cur += sizeof(uint64_t);
				}
				if (found == 0) {
					logger(LL_ERROR, "Incompatible Pongo image\n");
					return -1;
				}
			}
			
			// check module flags
			uint64_t kpf_flag = 0;
			uint64_t cpf_flag = 0;
			uint64_t sep_racer_flag = 0;
			uint64_t ramdisk_flag = 0;
			
			logger(LL_INFO, "Loading image flags...\n");
			
			if (rdsk_type != 0) {
				if (
					load_rdsk_flag(
								   (const uint8_t*)gRAMDisk,
								   gRAMDiskLength,
								   (rdsk_type & (RDSK_TYPE_UNION_IOS | RDSK_TYPE_UNION_TVOS)) ? 0x2222 : 0x1111,
								   "RAMDisk.dmg",
								   &ramdisk_flag
								   )
					)
				{
					logger(LL_ERROR, "Image flag not found: %s\n", "RAMDisk.dmg");
					return -2;
				}
			}
			if (load_module_flag((const uint8_t*)gCPF, gCPFLength, 0xAAAA000000009990uLL, "cpf", &cpf_flag)) {
				logger(LL_ERROR, "Image flag not found: %s\n", "cpf");
				return -2;
			}
			if (load_module_flag((const uint8_t*)gKPF, gKPFLength, 0xBBBB000000009990uLL, "kpf", &kpf_flag)) {
				logger(LL_ERROR, "Image flag not found: %s\n", "kpf");
				return -2;
			}
			if (load_module_flag((const uint8_t*)gSEPRacer, gSEPRacerLength, 0xCCCC000000009990uLL, "sep_racer", &sep_racer_flag)) {
				logger(LL_ERROR, "Image flag not found: %s\n", "sep_racer");
				return -2;
			}
			client->kpf_flag = kpf_flag;
			client->cpf_flag = cpf_flag;
			client->sep_racer_flag = sep_racer_flag;
			client->ramdisk_flag = ramdisk_flag;
			
			// check module compatibility
			logger(LL_INFO, "Checking image flags...\n");
			int module_unsupported = 0;
			uint64_t vflag = convert_cpid_bdid_to_plat_vflag(client->cpid, client->bdid);
			int is_tvos = is_tvos_with_cpid_bdid(client->cpid, client->bdid);
			if (is_tvos == -1) {
				logger(LL_ERROR, "Unknown bdid (BDID: 0x%02x)\n", (uint8_t)client->bdid);
				module_unsupported = 1;
			}
			if (rdsk_type != 0) {
				if (0 == check_vflag(client->ramdisk_flag, vflag)) {
					logger(LL_ERROR, "Found unsupported module (name: %s)\n", "RAMDisk.dmg");
					module_unsupported = 1;
				}
			}
			if (!is_a8_variant_soc(client->cpid)) {
				if (0 == check_vflag(client->cpf_flag, vflag)) {
					logger(LL_ERROR, "Found unsupported module (name: %s)\n", "cpf");
					module_unsupported = 1;
				}
			}
			if (0 == check_vflag(client->kpf_flag, vflag)) {
				logger(LL_ERROR, "Found unsupported module (name: %s)\n", "kpf");
				module_unsupported = 1;
			}
			if (0 == check_vflag(client->sep_racer_flag, vflag)) {
				logger(LL_ERROR, "Found unsupported module (name: %s)\n", "sep_racer");
				module_unsupported = 1;
			}
			
			if (module_unsupported) {
				logger(LL_ERROR, "Unsupported device (CPID: %04x)\n", client->cpid);
				return -2;
			}
			
			// check bsep
			if (client->flags & FLAG_FETCH_BSEP) {
				if (is_a10_variant_soc(client->cpid)) {
					logger(LL_ERROR, "This device does not requires SEP ciphertext block\n");
					return -2;
				}
			}
			if (client->sep_shellcode_block && client->sep_shellcode_block_len) {
				if (client->sep_shellcode_block_len == 0x80) {
					logger(LL_INFO, "Found old style block!\n");
					uint8_t zero[0x10] = { 0 };
					memset(zero, 0, 0x10);
					if (memcmp(client->sep_shellcode_block + 0x30, zero, 0x10) || memcmp(client->sep_shellcode_block + 0x70, zero, 0x10)) {
						logger(LL_ERROR, "block type check failed!\n");
						return -2;
					}
				}
				else {
					logger(LL_INFO, "Checking block type...\n");
					bool _bsep_is_valid = 0;
					sep_block_t* bsep = (sep_block_t*)client->sep_shellcode_block;
					uint32_t myType = 0;
					if (get_bsep_type(bsep, &myType) == false) {
						logger(LL_ERROR, "block type check failed!\n");
						return -2;
					}
					if ((myType == BSEP_TYPE_SHC) && (client->flags & FLAG_LOAD_BSEP_SHC)) {
						_bsep_is_valid = 1;
					}
					if ((myType == BSEP_TYPE_PTE) && (client->flags & FLAG_LOAD_BSEP_PTE)) {
						_bsep_is_valid = 1;
					}
					if (!_bsep_is_valid) {
						logger(LL_ERROR, "Invalid block type!\n");
						return -2;
					}
				}
			}
			
			if (client->flags & FLAG_TETHERED) {
				logger(LL_INFO, "Checking image version flags...\n");
				int is_tvos = is_tvos_with_cpid_bdid(client->cpid, client->bdid);
				uint64_t vflag = convert_build_to_ios_vflag(client->build_major);
				if (client->build_major >= 14) {
					if (0 == check_vflag(client->kpf_flag, vflag)) {
						logger(LL_ERROR, "Found unsupported module (name: %s)\n", "kpf");
						return -1;
					}
					if (0 == check_vflag(client->ramdisk_flag, vflag)) {
						logger(LL_ERROR, "Found unsupported module (name: %s)\n", "RAMDisk.dmg");
						return -1;
					}
				}
			}
		}
		
		logger(LL_DEBUG, "Found supported device (CPID: %04x)\n", client->cpid);
	}
#endif

	client->image4supported = is_image4_supported(client);
	logger(LL_INFO, "Device supports Image4: %s\n", (client->image4supported) ? "true" : "false");

	// choose whether this is an upgrade or a restore (default to upgrade)
	client->tss = NULL;
	plist_t build_identity = NULL;
	int build_identity_needs_free = 0;
	if (client->flags & FLAG_CUSTOM) {
		build_identity = plist_new_dict();
		build_identity_needs_free = 1;
		{
			plist_t node;
			plist_t comp;
			plist_t inf;
			plist_t manifest;

			char tmpstr[256];
			char p_all_flash[128];
			char lcmodel[8];
			strcpy(lcmodel, client->device->hardware_model);
			int x = 0;
			while (lcmodel[x]) {
				lcmodel[x] = tolower(lcmodel[x]);
				x++;
			}

			snprintf(p_all_flash, sizeof(p_all_flash), "Firmware/all_flash/all_flash.%s.%s", lcmodel, "production");
			strcpy(tmpstr, p_all_flash);
			strcat(tmpstr, "/manifest");

			// get all_flash file manifest
			char *files[16];
			void *fmanifest = NULL;
			size_t msize = 0;
			if (ipsw_extract_to_memory(client->ipsw, tmpstr, &fmanifest, &msize) < 0) {
				logger(LL_ERROR, "could not extract %s from IPSW\n", tmpstr);
				free(build_identity);
				return -1;
			}

			char *tok = strtok(fmanifest, "\r\n");
			int fc = 0;
			while (tok) {
				files[fc++] = strdup(tok);
				if (fc >= 16) {
					break;
				}
				tok = strtok(NULL, "\r\n");
			}
			free(fmanifest);

			manifest = plist_new_dict();

			for (x = 0; x < fc; x++) {
				inf = plist_new_dict();
				strcpy(tmpstr, p_all_flash);
				strcat(tmpstr, "/");
				strcat(tmpstr, files[x]);
				plist_dict_set_item(inf, "Path", plist_new_string(tmpstr));
				comp = plist_new_dict();
				plist_dict_set_item(comp, "Info", inf);
				const char* compname = get_component_name(files[x]);
				if (compname) {
					plist_dict_set_item(manifest, compname, comp);
					if (!strncmp(files[x], "DeviceTree", 10)) {
						plist_dict_set_item(manifest, "RestoreDeviceTree", plist_copy(comp));
					}
				} else {
					logger(LL_WARNING, "Unhandled component %s\n", files[x]);
					plist_free(comp);
				}
				free(files[x]);
				files[x] = NULL;
			}

			// add iBSS
			snprintf(tmpstr, sizeof(tmpstr), "Firmware/dfu/iBSS.%s.%s.dfu", lcmodel, "RELEASE");
			inf = plist_new_dict();
			plist_dict_set_item(inf, "Path", plist_new_string(tmpstr));
			comp = plist_new_dict();
			plist_dict_set_item(comp, "Info", inf);
			plist_dict_set_item(manifest, "iBSS", comp);

			// add iBEC
			snprintf(tmpstr, sizeof(tmpstr), "Firmware/dfu/iBEC.%s.%s.dfu", lcmodel, "RELEASE");
			inf = plist_new_dict();
			plist_dict_set_item(inf, "Path", plist_new_string(tmpstr));
			comp = plist_new_dict();
			plist_dict_set_item(comp, "Info", inf);
			plist_dict_set_item(manifest, "iBEC", comp);

			// add kernel cache
			plist_t kdict = NULL;

			node = plist_dict_get_item(client->build_manifest, "KernelCachesByTarget");
			if (node && (plist_get_node_type(node) == PLIST_DICT)) {
				char tt[4];
				strncpy(tt, lcmodel, 3);
				tt[3] = 0;
				kdict = plist_dict_get_item(node, tt);
			} else {
				// Populated in older iOS IPSWs
				kdict = plist_dict_get_item(client->build_manifest, "RestoreKernelCaches");
			}
			if (kdict && (plist_get_node_type(kdict) == PLIST_DICT)) {
				plist_t kc = plist_dict_get_item(kdict, "Release");
				if (kc && (plist_get_node_type(kc) == PLIST_STRING)) {
					inf = plist_new_dict();
					plist_dict_set_item(inf, "Path", plist_copy(kc));
					comp = plist_new_dict();
					plist_dict_set_item(comp, "Info", inf);
					plist_dict_set_item(manifest, "KernelCache", comp);
					plist_dict_set_item(manifest, "RestoreKernelCache", plist_copy(comp));
				}
			}

			// add ramdisk
			node = plist_dict_get_item(client->build_manifest, "RestoreRamDisks");
			if (node && (plist_get_node_type(node) == PLIST_DICT)) {
				plist_t rd = plist_dict_get_item(node, (client->flags & FLAG_ERASE) ? "User" : "Update");
				// if no "Update" ram disk entry is found try "User" ram disk instead
				if (!rd && !(client->flags & FLAG_ERASE)) {
					rd = plist_dict_get_item(node, "User");
					// also, set the ERASE flag since we actually change the restore variant
					client->flags |= FLAG_ERASE;
				}
				if (rd && (plist_get_node_type(rd) == PLIST_STRING)) {
					inf = plist_new_dict();
					plist_dict_set_item(inf, "Path", plist_copy(rd));
					comp = plist_new_dict();
					plist_dict_set_item(comp, "Info", inf);
					plist_dict_set_item(manifest, "RestoreRamDisk", comp);
				}
			}

			// add OS filesystem
			node = plist_dict_get_item(client->build_manifest, "SystemRestoreImages");
			if (!node) {
				logger(LL_ERROR, "missing SystemRestoreImages in Restore.plist\n");
			}
			plist_t os = plist_dict_get_item(node, "User");
			if (!os) {
				logger(LL_ERROR, "missing filesystem in Restore.plist\n");
			} else {
				inf = plist_new_dict();
				plist_dict_set_item(inf, "Path", plist_copy(os));
				comp = plist_new_dict();
				plist_dict_set_item(comp, "Info", inf);
				plist_dict_set_item(manifest, "OS", comp);
			}

			// add info
			inf = plist_new_dict();
			plist_dict_set_item(inf, "RestoreBehavior", plist_new_string((client->flags & FLAG_ERASE) ? "Erase" : "Update"));
			plist_dict_set_item(inf, "Variant", plist_new_string((client->flags & FLAG_ERASE) ? "Customer " RESTORE_VARIANT_ERASE_INSTALL : "Customer " RESTORE_VARIANT_UPGRADE_INSTALL));
			plist_dict_set_item(build_identity, "Info", inf);

			// finally add manifest
			plist_dict_set_item(build_identity, "Manifest", manifest);
		}
	} else if (client->restore_variant) {
		build_identity = build_manifest_get_build_identity_for_model_with_variant(client->build_manifest, client->device->hardware_model, client->restore_variant, 1);
	} else if (client->flags & FLAG_ERASE) {
		build_identity = build_manifest_get_build_identity_for_model_with_variant(client->build_manifest, client->device->hardware_model, RESTORE_VARIANT_ERASE_INSTALL, 0);
	} else {
		build_identity = build_manifest_get_build_identity_for_model_with_variant(client->build_manifest, client->device->hardware_model, RESTORE_VARIANT_UPGRADE_INSTALL, 0);
		if (!build_identity) {
			build_identity = build_manifest_get_build_identity_for_model(client->build_manifest, client->device->hardware_model);
		}
	}
	if (build_identity == NULL) {
		logger(LL_ERROR, "Unable to find a matching build identity\n");
		return -1;
	}

	client->macos_variant = build_manifest_get_build_identity_for_model_with_variant(client->build_manifest, client->device->hardware_model, RESTORE_VARIANT_MACOS_RECOVERY_OS, 1);

	/* print information about current build identity */
	build_identity_print_information(build_identity);

#ifdef HAVE_TURDUS_MERULA
	bool has_bb = false;
	bool has_se = false;
#define USE_SIGNED_BBFW (1u << 0)
#define USE_SIGNED_SEFW (1u << 1)
#define USE_SIGNED_RSEP (1u << 2)
#define USE_SIGNED_BASE (1u << 3)
	uint32_t fw_component_flag = 0;
	uint32_t specific_fw_component_flag = 0;
	if (client->flags & FLAG_DOWNGRADE) {
		// check cryptex1 ticket
		if (
			!(client->flags & FLAG_TETHERED) && // !tethered
			!(client->flags & FLAG_FETCH_BSEP)  // !pongoonly
			)
		{
			if (build_identity_has_component(build_identity, "Cryptex1,AppOS") || build_identity_has_component(build_identity, "Cryptex1,SystemOS")) {
				// need 'Cryptex1,Ticket'
				int _found = 0;
				logger(LL_DEBUG, "Checking Cryptex1,Ticket\n");
				if (plist_dict_get_item(client->local_shsh, "Cryptex1,Ticket")) {
					_found = 1;
				}
				else {
					plist_t cryptex1_tss = plist_dict_get_item(client->local_shsh, "cryptexTicket");
					if (cryptex1_tss) {
						if (plist_dict_get_item(cryptex1_tss, "Cryptex1,Ticket")) {
							_found = 1;
						}
					}
				}
				if (_found != 1) {
					logger(LL_ERROR, "no Cryptex1,Ticket\n");
					return -1;
				}
				
				logger(LL_DEBUG, "Checking cryptexSeed\n");
				plist_t cnonce_node = plist_dict_get_item(client->local_shsh, "cryptexSeed");
				if (cnonce_node) {
					char* cstr = NULL;
					plist_get_string_val(cnonce_node, &cstr);
					if (cstr) {
						void* cstr_ptr = (void*)cstr;
						if (strlen(cstr) != 34) {
							logger(LL_ERROR, "Wrong nonce seed size\n");
							return -1;
						}
						if (!(cstr[0] == '0') || !(cstr[1] == 'x')) {
							logger(LL_ERROR, "Wrong nonce seed type\n");
							return -1;
						}
						cstr += 2;
						client->cryptex1_nonce_seed = strdup(cstr);
						logger(LL_INFO, "cryptexSeed = %s\n", client->cryptex1_nonce_seed);
						_found = 2;
						free(cstr_ptr);
						cstr = NULL;
						cstr_ptr = NULL;
					}
				}
				if (_found != 2) {
					logger(LL_ERROR, "no cryptexSeed\n");
					return -1;
				}
				if (0 == check_vflag(client->cpf_flag, convert_build_to_ios_vflag(client->build_major))) {
					logger(LL_ERROR, "Found unsupported module (name: %s)\n", "cpf");
					return -1;
				}
			}
		}
		
		/* check firmware components */
		if (build_identity_has_component(build_identity, "BasebandFirmware")) {
			has_bb = true;
			
			int is_MDM9645 = 0;
			if (
				(client->cpid == 0x8010 && ((client->bdid == 0x08) || (client->bdid == 0x0A))) ||
				(client->cpid == 0x8011 && ((client->bdid == 0x0E) || (client->bdid == 0x06)))
				)
			{
				is_MDM9645 = 1;
			}
			
			/* If the latest baseband is not compatible with the firmware, please mark it here. */
			int is_bb_incompatible = 0;
			if (is_MDM9645 && client->build_major == 14) {
				is_bb_incompatible = 1;
			}
			
			if (is_bb_incompatible) {
				if (client->flags & FLAG_INTERACTIVE) {
					char input[64];
					printf("############################ [ WARNING ] #############################\n"
						   "# You are trying to restore to a version that does not have baseband #\n"
						   "# compatibility. Restore might work, but it will not enable cellular #\n"
						   "# and will mean you will have baseband issues.                       #\n"
						   "# If you want to continue, please type YES and press ENTER.          #\n"
						   "######################################################################\n");
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
						}
						else {
							printf("Invalid input. Please type YES or hit CTRL+C to abort.\n");
							continue;
						}
					}
				}
			}
		}
		
		if (build_identity_has_component(build_identity, "SE,UpdatePayload") || build_identity_has_component(build_identity, "SE,Firmware")) {
			has_se = true;
		}
		
		// BBFW
		if (
			has_bb &&
			!(client->flags & FLAG_FETCH_BSEP)  // !pongoonly
			)
		{
			fw_component_flag |= USE_SIGNED_BBFW;
			if (client->bbfw.data && client->bbfw.length && client->bbfw.manifest) {
				specific_fw_component_flag |= USE_SIGNED_BBFW;
			}
		}
		
		// SEFW
		if (
			has_se &&
			!(client->flags & FLAG_FETCH_BSEP)  // !pongoonly
			)
		{
			fw_component_flag |= USE_SIGNED_SEFW;
			if (client->sefw.data && client->sefw.length && client->sefw.manifest) {
				specific_fw_component_flag |= USE_SIGNED_SEFW;
			}
		}
		
		// RSEP
		if (
			is_a10_variant_soc(client->cpid) ||    // A10 variant
			(client->flags & FLAG_LOAD_BSEP_SHC) || // do fwload race
			(client->flags & FLAG_TETHERED)        // tethered
			)
		{
			fw_component_flag |= USE_SIGNED_RSEP;
			if (client->rsep.data && client->rsep.length && client->rsep.manifest) {
				specific_fw_component_flag |= USE_SIGNED_RSEP;
			}
		}
		
		// Base
		if (
			(client->build_major <= 13 && have_arm64_second_stage_iboot(client->cpid)) || // ios <= 9
			(client->flags & FLAG_TETHERED) || // tethered
			(client->flags & FLAG_FETCH_BSEP)  // pongoonly
			)
		{
			fw_component_flag |= USE_SIGNED_BASE;
			if (client->base.manifest) { // no data/length
				specific_fw_component_flag |= USE_SIGNED_BASE;
			}
		}
		
		if ((fw_component_flag == 0) && (specific_fw_component_flag != 0)) {
			logger(LL_ERROR, "Firmware component flag does not matched. wtf...\n");
			return -1;
		}
		if (specific_fw_component_flag && (fw_component_flag != specific_fw_component_flag)) {
			logger(LL_ERROR, "Firmware component flag does not matched. arg is incomplete or incorrect.\n");
			return -1;
		}
		
		/* download latest firmware components */
		fragmentzip_t *fragment = NULL;
		if ((fw_component_flag != 0) && (specific_fw_component_flag == 0)) {
			char fwselectname[256] = "";
			if (fw_component_flag & USE_SIGNED_BBFW) {
				strcat(fwselectname, "Baseband");
			}
			if (fw_component_flag & USE_SIGNED_SEFW) {
				if (fwselectname[0] != '\0') {
					strcat(fwselectname, "/");
				}
				strcat(fwselectname, "SE");
			}
			if (fw_component_flag & USE_SIGNED_RSEP) {
				if (fwselectname[0] != '\0') {
					strcat(fwselectname, "/");
				}
				strcat(fwselectname, "RestoreSEP");
			}
			if (fw_component_flag & USE_SIGNED_BASE) {
				if (fwselectname[0] != '\0') {
					strcat(fwselectname, "/");
				}
				strcat(fwselectname, "Base");
			}
			if (fwselectname[0] == '\0') {
				strcpy(fwselectname, "None"); // It never happen but
			}
			
			char *fwurl = NULL;
			unsigned char fwsha1[20];
			unsigned char *p_fwsha1 = NULL;
			plist_t signed_fws = NULL;
			int res = ipsw_get_signed_firmwares(client->device->product_type, &signed_fws);
			if (res < 0) {
				logger(LL_ERROR, "Could not fetch list of signed firmwares.\n");
				return res;
			}
			uint32_t count = plist_array_get_size(signed_fws);
			if (count == 0) {
				plist_free(signed_fws);
				logger(LL_ERROR, "No firmwares are currently being signed for %s (REALLY?!)\n", client->device->product_type);
				return -1;
			}
			plist_t selected_fw = NULL;
			if (client->flags & FLAG_INTERACTIVE) {
				uint32_t i = 0;
				logger(LL_INFO, "The following firmwares are currently being signed for %s:\n", client->device->product_type);
				for (i = 0; i < count; i++) {
					plist_t fw = plist_array_get_item(signed_fws, i);
					plist_t p_version = plist_dict_get_item(fw, "version");
					plist_t p_build = plist_dict_get_item(fw, "buildid");
					char *s_version = NULL;
					char *s_build = NULL;
					plist_get_string_val(p_version, &s_version);
					plist_get_string_val(p_build, &s_build);
					logger(LL_INFO, "  [%d] %s (build %s)\n", i+1, s_version, s_build);
					free(s_version);
					free(s_build);
				}
				while (1) {
					char input[64];
					printf("Select the firmware you want to use for the %s: ", fwselectname);
					fflush(stdout);
					fflush(stdin);
					get_user_input(input, 63, 0);
					if (*input == '\0') {
						plist_free(signed_fws);
						return -1;
					}
					if (client->flags & FLAG_QUIT) {
						return -1;
					}
					unsigned long selected = strtoul(input, NULL, 10);
					if (selected == 0 || selected > count) {
						printf("Invalid input value. Must be in range: 1..%u\n", count);
						continue;
					}
					selected_fw = plist_array_get_item(signed_fws, (uint32_t)selected-1);
					break;
				}
			}
			else {
				logger(LL_INFO, "NOTE: Running non-interactively, automatically selecting latest available version\n");
				selected_fw = plist_array_get_item(signed_fws, 0);
			}
			if (!selected_fw) {
				logger(LL_ERROR, "Failed to select latest firmware?!\n");
				plist_free(signed_fws);
				return -1;
			}
			else {
				plist_t p_version = plist_dict_get_item(selected_fw, "version");
				plist_t p_build = plist_dict_get_item(selected_fw, "buildid");
				char *s_version = NULL;
				char *s_build = NULL;
				plist_get_string_val(p_version, &s_version);
				plist_get_string_val(p_build, &s_build);
				logger(LL_INFO, "Selected %s version %s (build %s)\n", fwselectname, s_version, s_build);
				free(s_version);
				free(s_build);
				plist_t p_url = plist_dict_get_item(selected_fw, "url");
				plist_t p_sha1 = plist_dict_get_item(selected_fw, "sha1sum");
				char *s_sha1 = NULL;
				plist_get_string_val(p_url, &fwurl);
				plist_get_string_val(p_sha1, &s_sha1);
				if (strlen(s_sha1) == 40) {
					int i;
					int v;
					for (i = 0; i < 40; i+=2) {
						v = 0;
						sscanf(s_sha1+i, "%02x", &v);
						fwsha1[i/2] = (unsigned char)v;
					}
					p_fwsha1 = &fwsha1[0];
				}
				else {
					logger(LL_ERROR, "Unexpected size of sha1sum\n");
				}
			}
			plist_free(signed_fws);
			
			if (!fwurl || !p_fwsha1) {
				logger(LL_ERROR, "Missing firmware URL or SHA1\n");
				return -1;
			}
			
			char* ipsw = NULL;
			logger(LL_DEBUG, "Firmware url: %s\n", fwurl);
			fragment = fragmentzip_open(fwurl);
			if (!fragment) {
				logger(LL_ERROR, "Could not open fragmentzip\n");
				return -1;
			}
			
			char* manifest_bin = NULL;
			size_t manifest_len = 0;
			logger(LL_INFO, "Downloading %s\n", "BuildManifest.plist");
			if (fragmentzip_download_to_memory(fragment, "BuildManifest.plist", &manifest_bin, &manifest_len, NULL)) {
				logger(LL_ERROR, "Could not find %s\n", "BuildManifest.plist");
				fragmentzip_close(fragment);
				return -1;
			}
			if (!manifest_bin) {
				logger(LL_ERROR, "Could not allocate %s buffer\n", "BuildManifest.plist");
				fragmentzip_close(fragment);
				return -1;
			}
			logger(LL_DEBUG, "manifest length: %zu\n", manifest_len);
			
			if (memcmp(manifest_bin, "bplist00", 8) == 0) {
				if (fw_component_flag & USE_SIGNED_BBFW) {
					plist_from_bin((const char *)manifest_bin, manifest_len, &client->bbfw.manifest);
				}
				if (fw_component_flag & USE_SIGNED_SEFW) {
					plist_from_bin((const char *)manifest_bin, manifest_len, &client->sefw.manifest);
				}
				if (fw_component_flag & USE_SIGNED_RSEP) {
					plist_from_bin((const char *)manifest_bin, manifest_len, &client->rsep.manifest);
				}
				if (fw_component_flag & USE_SIGNED_BASE) {
					plist_from_bin((const char *)manifest_bin, manifest_len, &client->base.manifest);
				}
			}
			else {
				if (fw_component_flag & USE_SIGNED_BBFW) {
					plist_from_xml((const char *)manifest_bin, manifest_len, &client->bbfw.manifest);
				}
				if (fw_component_flag & USE_SIGNED_SEFW) {
					plist_from_xml((const char *)manifest_bin, manifest_len, &client->sefw.manifest);
				}
				if (fw_component_flag & USE_SIGNED_RSEP) {
					plist_from_xml((const char *)manifest_bin, manifest_len, &client->rsep.manifest);
				}
				if (fw_component_flag & USE_SIGNED_BASE) {
					plist_from_xml((const char *)manifest_bin, manifest_len, &client->base.manifest);
				}
			}
			free(manifest_bin);
			if (fw_component_flag & USE_SIGNED_BBFW) {
				if (!client->bbfw.manifest) {
					logger(LL_ERROR, "Could not allocate BuildManifest for BasebandFirmware\n");
					return -1;
				}
			}
			if (fw_component_flag & USE_SIGNED_SEFW) {
				if (!client->sefw.manifest) {
					logger(LL_ERROR, "Could not allocate BuildManifest for SE Firmware\n");
					return -1;
				}
			}
			if (fw_component_flag & USE_SIGNED_RSEP) {
				if (!client->rsep.manifest) {
					logger(LL_ERROR, "Could not allocate BuildManifest for RestoreSEP\n");
					return -1;
				}
			}
			if (fw_component_flag & USE_SIGNED_BASE) {
				if (!client->base.manifest) {
					logger(LL_ERROR, "Could not allocate BuildManifest for Base Firmware\n");
					return -1;
				}
			}
		}
		
		// BBFW
		if (fw_component_flag & USE_SIGNED_BBFW) {
			// load identity
			if (get_identity_for_component(client, &client->bbfw) != 0) {
				logger(LL_ERROR, "Unable to find a matching build identity for BasebandFirmware\n");
				if (fragment) {
					fragmentzip_close(fragment);
				}
				return -1;
			}
			// download fw
			logger(LL_INFO, "BasebandFirmware manifest information\n");
			build_identity_print_information(client->bbfw.identity);
			
			if (download_component_by_name(fragment, "BasebandFirmware", NULL, &client->bbfw) != 0) {
				logger(LL_ERROR, "Unable to download BasebandFirmware\n");
				if (fragment) {
					fragmentzip_close(fragment);
				}
				return -1;
			}
		}
		
		// SEFW
		if (fw_component_flag & USE_SIGNED_SEFW) {
			// load identity
			if (get_identity_for_component(client, &client->sefw) != 0) {
				logger(LL_ERROR, "Unable to find a matching build identity for SE Firmware\n");
				if (fragment) {
					fragmentzip_close(fragment);
				}
				return -1;
			}
			// download fw
			logger(LL_INFO, "SE Firmware manifest information\n");
			build_identity_print_information(client->sefw.identity);
			
			if (download_component_by_name(fragment, "SE,UpdatePayload", "SE,Firmware", &client->sefw) != 0) {
				logger(LL_ERROR, "Unable to download SE Firmware\n");
				if (fragment) {
					fragmentzip_close(fragment);
				}
				return -1;
			}
		}
		
		// RSEP
		if (fw_component_flag & USE_SIGNED_RSEP) {
			// load identity
			if (get_identity_for_component(client, &client->rsep) != 0) {
				logger(LL_ERROR, "Unable to find a matching build identity for RestoreSEP\n");
				if (fragment) {
					fragmentzip_close(fragment);
				}
				return -1;
			}
			// download fw
			logger(LL_INFO, "RestoreSEP manifest information\n");
			build_identity_print_information(client->rsep.identity);
			
			if (download_component_by_name(fragment, "RestoreSEP", NULL, &client->rsep) != 0) {
				logger(LL_ERROR, "Unable to download RestoreSEP\n");
				if (fragment) {
					fragmentzip_close(fragment);
				}
				return -1;
			}
		}
		
		// Base
		if (fw_component_flag & USE_SIGNED_BASE) {
			// load identity
			if (get_identity_for_component(client, &client->base) != 0) {
				logger(LL_ERROR, "Unable to find a matching build identity for Base Firmware\n");
				if (fragment) {
					fragmentzip_close(fragment);
				}
				return -1;
			}
			
			logger(LL_INFO, "Base Firmware manifest information\n");
			build_identity_print_information(client->base.identity);
			
			if (client->build_major <= 13 && have_arm64_second_stage_iboot(client->cpid)) { // ios <= 9
				if (download_component_by_name(fragment, "iBSS", NULL, &client->base) != 0) {
					logger(LL_ERROR, "Unable to download iBSS\n");
					if (fragment) {
						fragmentzip_close(fragment);
					}
					return -1;
				}
			}
			
			if (client->flags & FLAG_TETHERED) { // tethered
#define DL_FW_COMP(name) { \
plist_t _item_node = plist_dict_get_item(manifest_node, #name); \
if (!_item_node || plist_get_node_type(_item_node) != PLIST_DICT) { \
logger(LL_ERROR, "Unable to find %s node\n", #name); \
if (fragment) { \
fragmentzip_close(fragment); \
} \
return -1; \
} \
plist_t _info_node = plist_dict_get_item(_item_node, "Info"); \
if (!_info_node || plist_get_node_type(_info_node) != PLIST_DICT) { \
logger(LL_ERROR, "Unable to find Info node\n"); \
if (fragment) { \
fragmentzip_close(fragment); \
} \
return -1; \
} \
plist_t _node = plist_dict_get_item(_info_node, "Path"); \
if (!_node || plist_get_node_type(_node) != PLIST_STRING) { \
logger(LL_ERROR, "Unable to find Path node\n"); \
if (fragment) { \
fragmentzip_close(fragment); \
} \
return -1; \
} \
plist_get_string_val(_node, &value); \
logger(LL_INFO, "Downloading %s\n", value); \
char* tmp_buf = NULL; \
size_t tmp_len = 0; \
if (fragmentzip_download_to_memory(fragment, value, &tmp_buf, &tmp_len, NULL)) { \
logger(LL_ERROR, "Could not find %s\n", value); \
if (fragment) { \
fragmentzip_close(fragment); \
} \
free(value); \
return -1; \
} \
if (!tmp_buf) { \
logger(LL_ERROR, "Could not allocate %s buffer\n", value); \
if (fragment) { \
fragmentzip_close(fragment); \
} \
free(value); \
return -1; \
} \
client->t_##name.im4p.data = (uint8_t *)tmp_buf; \
client->t_##name.im4p.length = tmp_len; \
logger(LL_DEBUG, "%s length: %zu\n", #name, client->t_##name.im4p.length); \
}
				char* value = NULL;
				plist_t manifest_node = NULL;
				
				manifest_node = plist_dict_get_item(client->base.identity, "Manifest");
				if (!manifest_node || plist_get_node_type(manifest_node) != PLIST_DICT) {
					logger(LL_ERROR, "Unable to find Manifest node\n");
					if (fragment) {
						fragmentzip_close(fragment);
					}
					return -1;
				}
				
				DL_FW_COMP(LLB);
				DL_FW_COMP(iBoot);
				DL_FW_COMP(AppleLogo);
				DL_FW_COMP(RecoveryMode);
				if (client->device->product_type && strncmp(client->device->product_type, "AppleTV", 7) == 0) {
					// AppleTV
				}
				else {
					DL_FW_COMP(BatteryCharging0);
					DL_FW_COMP(BatteryCharging1);
					DL_FW_COMP(BatteryFull);
					DL_FW_COMP(BatteryLow0);
					DL_FW_COMP(BatteryLow1);
					DL_FW_COMP(BatteryPlugin);
				}
			}
		}
	
		if (fragment) {
			fragmentzip_close(fragment);
		}
	}
	
	if (client->flags & FLAG_TETHERED) { // tethered
		int is_supported_version = 0;
		if (
			client->build_major == 10 || // iOS 6
			client->build_major == 13 || // iOS 9
			client->build_major == 14 || // iOS 10
			client->build_major == 15 || // iOS 11
			client->build_major == 17 || // iOS/iPadOS 13
			client->build_major == 18 || // iOS/iPadOS 14
			client->build_major == 19 || // iOS/iPadOS 15
			client->build_major == 20 || // iPadOS 16
			client->build_major == 21    // iPadOS 17
			)
		{
			is_supported_version = 1;
		}
		
		// iOS 7
		if (client->build_major == 11) {
			// DEBUG: pass
		}
		
		// iOS 8
		if (client->build_major == 12) {
			// DEBUG: pass
		}
		
		// iOS 12
		if (client->build_major == 16) {
			if (
				strncmp(client->version, "12.0", 4) == 0 ||
				strncmp(client->version, "12.1", 4) == 0 ||
				strncmp(client->version, "12.2", 4) == 0 ||
				strncmp(client->version, "12.3", 4) == 0 ||
				strncmp(client->version, "12.4", 4) == 0
				)
			{
				is_supported_version = 1;
			}
		}
		
		// iPadOS 18
		if (client->build_major == 22) {
			if (
				strncmp(client->version, "18.0", 4) == 0 ||
				strncmp(client->version, "18.1", 4) == 0 ||
				strncmp(client->version, "18.2", 4) == 0 ||
				strncmp(client->version, "18.3", 4) == 0 ||
				strncmp(client->version, "18.4", 4) == 0 ||
				strncmp(client->version, "18.5", 4) == 0 ||
				strncmp(client->version, "18.6", 4) == 0 ||
				strncmp(client->version, "18.7", 4) == 0
				)
			{
				is_supported_version = 1;
			}
		}
		
		// tvOS 26
		if (client->build_major == 23) {
			if (
				strncmp(client->version, "26.0", 4) == 0 ||
				strncmp(client->version, "26.1", 4) == 0 ||
				strncmp(client->version, "26.2", 4) == 0
				)
			{
				is_supported_version = 1;
			}
		}
		
		if (!is_supported_version) {
			if (!(client->flags & FLAG_ALLOW_UNSUPPORTED)) {
				logger(LL_ERROR, "Unsupported this ios version yet\n");
				return -1;
			}
			logger(LL_WARNING, "Unsupported ios version\n");
		}
	}
#endif

	if (client->macos_variant) {
		logger(LL_INFO, "Performing macOS restore\n");
	}

	if (client->mode == MODE_NORMAL && !(client->flags & FLAG_ERASE) && !(client->flags & FLAG_SHSHONLY)) {
		if (client->device_version && (compare_versions(client->device_version, client->version) > 0)) {
			if (client->flags & FLAG_INTERACTIVE) {
				char msgtext[512];
				snprintf(msgtext, 512, "You are trying to DOWNGRADE a %s device with an IPSW for %s while\n"
				    "trying to preserve the user data (Upgrade restore). This *might* work, but\n"
				    "there is a VERY HIGH chance it might FAIL BADLY with COMPLETE DATA LOSS.\n"
				    "If you want to take the risk (and have a backup of your important data!) you may continue.\n"
				    "You have been warned.\n", client->device_version, client->version);
				int pres = prompt_user("WARNING", msgtext);
				if (pres < 0) {
					client->flags |= FLAG_QUIT;
					return -1;
				}
			}
		}
	}

	if (client->flags & FLAG_ERASE && client->flags & FLAG_INTERACTIVE) {
		int pres = prompt_user(
		    "WARNING",
		    "You are about to perform an *ERASE* restore. ALL DATA on the target device will be IRREVERSIBLY DESTROYED. If you want to update your device without erasing the user data, cancel now and restart without -e or --erase command line switch.\n"
		);
		if (pres < 0) {
			client->flags |= FLAG_QUIT;
			return -1;
		}
#if 0
		char input[64];
		printf("################################ [ WARNING ] #################################\n"
		       "# You are about to perform an *ERASE* restore. ALL DATA on the target device #\n"
		       "# will be IRREVERSIBLY DESTROYED. If you want to update your device without  #\n"
		       "# erasing the user data, hit CTRL+C now and restart without -e or --erase    #\n"
		       "# command line switch.                                                       #\n"
		       "# If you want to continue with the ERASE, please type YES and press ENTER.   #\n"
		       "##############################################################################\n");
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
#endif
	}

#ifdef HAVE_TURDUS_MERULA
	if (
		(client->flags & FLAG_DOWNGRADE) &&
		is_arm64_soc(client->cpid) &&
		(client->flags & FLAG_FETCH_BSEP_PTE) &&
		!(client->flags & FLAG_LOAD_BSEP_SHC)
		)
	{
		if (is_a8_variant_soc(client->cpid)) {
			// DEBUG: PASS
		}
		else {
			logger(LL_ERROR, "This option is currently not supported in this version.\n");
			return -1;
		}
		// TODO: deprecated
		if (client->flags & FLAG_INTERACTIVE) {
			char input[64];
			printf("################################ [ WARNING ] #################################\n"
				   "# This mode writes to memory beyond TZ bounds, but there are no guarantees   #\n"
				   "# that these writes are safe.                                                #\n"
				   "# If you want to continue, please type YES and press ENTER.                  #\n"
				   "##############################################################################\n");
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
#endif
	idevicerestore_progress(client, RESTORE_STEP_PREPARE, 0.0);

	/* check if all components we need are actually there */
	logger(LL_INFO, "Checking IPSW for required components...\n");
	if (build_identity_check_components_in_ipsw(build_identity, client->ipsw) < 0) {
		logger(LL_ERROR, "Could not find all required components in IPSW %s\n", client->ipsw->path);
		return -1;
	}
	logger(LL_INFO, "All required components found in IPSW\n");

	/* Get OS (filesystem) name from build identity */
	char* os_path = NULL;
	if (build_identity_get_component_path(build_identity, "OS", &os_path) < 0) {
		logger(LL_ERROR, "Unable to get path for filesystem component\n");
		return -1;
	}

	/* check if IPSW has OS component 'stored' in ZIP archive, otherwise we need to extract it */
	int needs_os_extraction = 0;
	if (client->ipsw->zip) {
		ipsw_file_handle_t zfile = ipsw_file_open(client->ipsw, os_path);
		if (zfile) {
			if (!zfile->seekable) {
				needs_os_extraction = 1;
			}
			ipsw_file_close(zfile);
		}
	}

	if (needs_os_extraction && !(client->flags & FLAG_SHSHONLY)) {
		char* tmpf = NULL;
		struct stat st;
		if (client->cache_dir) {
			memset(&st, '\0', sizeof(struct stat));
			if (stat(client->cache_dir, &st) < 0) {
				mkdir_with_parents(client->cache_dir, 0755);
			}
			char* ipsw_basename = strdup(path_get_basename(client->ipsw->path));
			char* p = strrchr(ipsw_basename, '.');
			if (p && isalpha(*(p+1))) {
				*p = '\0';
			}
			tmpf = string_build_path(client->cache_dir, ipsw_basename, NULL);
			mkdir_with_parents(tmpf, 0755);
			free(tmpf);
			tmpf = string_build_path(client->cache_dir, ipsw_basename, os_path, NULL);
			free(ipsw_basename);
		} else {
			tmpf = get_temp_filename(NULL);
			client->delete_fs = 1;
		}

		/* check if we already have it extracted */
		uint64_t fssize = 0;
		ipsw_get_file_size(client->ipsw, os_path, &fssize);
		memset(&st, '\0', sizeof(struct stat));
		if (stat(tmpf, &st) == 0) {
			if ((fssize > 0) && ((uint64_t)st.st_size == fssize)) {
				logger(LL_INFO, "Using cached filesystem from '%s'\n", tmpf);
				client->filesystem = tmpf;
			}
		}

		if (!client->filesystem) {
			logger(LL_INFO, "Extracting filesystem from IPSW: %s\n", os_path);
			if (ipsw_extract_to_file_with_progress(client->ipsw, os_path, tmpf, 1) < 0) {
				logger(LL_ERROR, "Unable to extract filesystem from IPSW\n");
				logger(LL_INFO, "Removing %s\n", tmpf);
				unlink(tmpf);
				free(tmpf);
				return -1;
			}
			client->filesystem = tmpf;
		}
	}

	idevicerestore_progress(client, RESTORE_STEP_PREPARE, 0.2);

#ifdef HAVE_TURDUS_MERULA
	if ((client->flags & FLAG_DOWNGRADE) && is_arm64_soc(client->cpid)) {
		if (!(client->flags & FLAG_FETCH_BSEP)) { // checks the hashes of several important firmware components
			logger(LL_INFO, "Checking hashes...\n");
			if (check_firmware_components(client, build_identity)) {
				return -1;
			}
		}
	}
#endif

	/* retrieve shsh blobs if required */
	if (tss_enabled) {
		int stashbag_commit_required = 0;

		if (client->mode == MODE_NORMAL && !(client->flags & FLAG_ERASE) && !(client->flags & FLAG_SHSHONLY)) {
			plist_t node = normal_get_lockdown_value(client, NULL, "HasSiDP");
			uint8_t needs_preboard = 0;
			if (node && plist_get_node_type(node) == PLIST_BOOLEAN) {
				plist_get_bool_val(node, &needs_preboard);
			}
			if (needs_preboard) {
				logger(LL_INFO, "Checking if device requires stashbag...\n");
				plist_t manifest;
				if (get_preboard_manifest(client, build_identity, &manifest) < 0) {
					logger(LL_ERROR, "Unable to create preboard manifest.\n");
					return -1;
				}
				logger(LL_DEBUG, "creating stashbag...\n");
				int err = normal_handle_create_stashbag(client, manifest);
				if (err < 0) {
					if (err == -2) {
						logger(LL_ERROR, "Could not create stashbag (timeout).\n");
					} else {
						logger(LL_ERROR, "An error occurred while creating the stashbag.\n");
					}
					return -1;
				} else if (err == 1) {
					stashbag_commit_required = 1;
				}
				plist_free(manifest);
			}
		}

		if (client->build_major > 8) {
			unsigned char* nonce = NULL;
			unsigned int nonce_size = 0;
			if (get_ap_nonce(client, &nonce, &nonce_size) < 0) {
				/* the first nonce request with older firmware releases can fail and it's OK */
				logger(LL_NOTICE, "Unable to get nonce from device\n");
			}

			if (!client->nonce || (nonce_size != client->nonce_size) || (memcmp(nonce, client->nonce, nonce_size) != 0)) {
				if (client->nonce) {
					free(client->nonce);
				}
				client->nonce = nonce;
				client->nonce_size = nonce_size;
			} else {
				free(nonce);
			}
			if (client->mode == MODE_NORMAL) {
				plist_t ap_params = normal_get_lockdown_value(client, NULL, "ApParameters");
				if (ap_params) {
					if (!client->parameters) {
						client->parameters = plist_new_dict();
					}
					plist_dict_merge(&client->parameters, ap_params);
					plist_t p_sep_nonce = plist_dict_get_item(ap_params, "SepNonce");
					uint64_t sep_nonce_size = 0;
					const char* sep_nonce = plist_get_data_ptr(p_sep_nonce, &sep_nonce_size);
					if (sep_nonce) {
						logger(LL_INFO, "Getting SepNonce in normal mode... ");
						logger_dump_hex(LL_INFO, sep_nonce, sep_nonce_size);
					}
					plist_free(ap_params);
				}
				plist_t req_nonce_slot = plist_access_path(build_identity, 2, "Info", "RequiresNonceSlot");
				if (req_nonce_slot) {
					plist_dict_set_item(client->parameters, "RequiresNonceSlot", plist_copy(req_nonce_slot));
				}
			}
		}

		if (client->flags & FLAG_QUIT) {
			return -1;
		}
		
		if (client->mode == MODE_RESTORE && client->root_ticket) {
			plist_t ap_ticket = plist_new_data((char*)client->root_ticket, client->root_ticket_len);
			if (!ap_ticket) {
				logger(LL_ERROR, "Failed to create ApImg4Ticket node value.\n");
				return -1;
			}
			client->tss = plist_new_dict();
			if (!client->tss) {
				logger(LL_ERROR, "Failed to create ApImg4Ticket node.\n");
				return -1;
			}
			plist_dict_set_item(client->tss, "ApImg4Ticket", ap_ticket);
		} else {
			if (get_tss_response(client, build_identity, &client->tss) < 0) {
				logger(LL_ERROR, "Unable to get SHSH blobs for this device\n");
				return -1;
			}
			if (client->macos_variant) {
				if (get_local_policy_tss_response(client, build_identity, &client->tss_localpolicy) < 0) {
					logger(LL_ERROR, "Unable to get SHSH blobs for this device (local policy)\n");
					return -1;
				}
				if (get_recoveryos_root_ticket_tss_response(client, build_identity, &client->tss_recoveryos_root_ticket) < 0) {
					logger(LL_ERROR, "Unable to get SHSH blobs for this device (recovery OS Root Ticket)\n");
					return -1;
				}
			} else {
				plist_t recovery_variant = plist_access_path(build_identity, 2, "Info", "RecoveryVariant");
				if (recovery_variant) {
					const char* recovery_variant_str = plist_get_string_ptr(recovery_variant, NULL);
					client->recovery_variant = build_manifest_get_build_identity_for_model_with_variant(client->build_manifest, client->device->hardware_model, recovery_variant_str, 1);
					if (!client->recovery_variant) {
						logger(LL_ERROR, "Variant '%s' not found in BuildManifest\n", recovery_variant_str);
						return -1;
					}
					if (get_tss_response(client, client->recovery_variant, &client->tss_recoveryos_root_ticket) < 0) {
						logger(LL_ERROR, "Unable to get SHSH blobs for this device (%s)\n", recovery_variant_str);
						return -1;
					}
				}
			}
		}

		if (stashbag_commit_required) {
			plist_t ticket = plist_dict_get_item(client->tss, "ApImg4Ticket");
			if (!ticket || plist_get_node_type(ticket) != PLIST_DATA) {
				logger(LL_ERROR, "Missing ApImg4Ticket in TSS response for stashbag commit\n");
				return -1;
			}
			logger(LL_INFO, "Committing stashbag...\n");
			int err = normal_handle_commit_stashbag(client, ticket);
			if (err < 0) {
				logger(LL_ERROR, "Could not commit stashbag (%d). Aborting.\n", err);
				return -1;
			}
		}
	}

	if (client->flags & FLAG_QUIT) {
		return -1;
	}
	if (client->flags & FLAG_SHSHONLY) {
		if (!tss_enabled) {
			logger(LL_INFO, "This device does not require a TSS record\n");
			return 0;
		}
		if (!client->tss) {
			logger(LL_ERROR, "could not fetch TSS record\n");
			return -1;
		} else {
			char *bin = NULL;
			uint32_t blen = 0;
			plist_to_bin(client->tss, &bin, &blen);
			if (bin) {
				char zfn[1024];
				if (client->cache_dir) {
					strcpy(zfn, client->cache_dir);
					strcat(zfn, "/shsh");
				} else {
					strcpy(zfn, "shsh");
				}
				mkdir_with_parents(zfn, 0755);
				snprintf(&zfn[0]+strlen(zfn), sizeof(zfn)-strlen(zfn), "/%" PRIu64 "-%s-%s.shsh", client->ecid, client->device->product_type, client->version);
				struct stat fst;
				if (stat(zfn, &fst) != 0) {
					gzFile zf = gzopen(zfn, "wb");
					gzwrite(zf, bin, blen);
					gzclose(zf);
					logger(LL_INFO, "SHSH saved to '%s'\n", zfn);
				} else {
					logger(LL_INFO, "SHSH '%s' already present.\n", zfn);
				}
				free(bin);
			} else {
				logger(LL_ERROR, "could not get TSS record data\n");
			}
			plist_free(client->tss);
			return 0;
		}
	}

	/* verify if we have tss records if required */
	if ((tss_enabled) && (client->tss == NULL)) {
		logger(LL_ERROR, "Unable to proceed without a TSS record.\n");
		return -1;
	}

	if ((tss_enabled) && client->tss) {
		/* fix empty dicts */
		fixup_tss(client->tss);
	}
	idevicerestore_progress(client, RESTORE_STEP_PREPARE, 0.25);
	if (client->flags & FLAG_QUIT) {
		return -1;
	}

	// if the device is in normal mode, place device into recovery mode
	if (client->mode == MODE_NORMAL) {
		logger(LL_INFO, "Entering recovery mode...\n");
		if (normal_enter_recovery(client) < 0) {
			logger(LL_ERROR, "Unable to place device into recovery mode from normal mode\n");
			if (client->tss)
				plist_free(client->tss);
			return -5;
		}
	}

	idevicerestore_progress(client, RESTORE_STEP_PREPARE, 0.3);
	if (client->flags & FLAG_QUIT) {
		return -1;
	}

	if (client->mode == MODE_DFU) {
		// if the device is in DFU mode, place it into recovery mode
		dfu_client_free(client);
		recovery_client_free(client);
#ifdef HAVE_LIMERA1N
		if ((client->flags & FLAG_CUSTOM) && limera1n_is_supported(client->device)) {
			logger(LL_INFO, "connecting to DFU\n");
			if (dfu_client_new(client) < 0) {
				return -1;
			}
			logger(LL_INFO, "exploiting with limera1n\n");
			if (limera1n_exploit(client->device, &client->dfu->client) != 0) {
				logger(LL_ERROR, "limera1n exploit failed\n");
				dfu_client_free(client);
				return -1;
			}
			dfu_client_free(client);
			logger(LL_INFO, "exploited\n");
		}
#endif
		if (dfu_enter_recovery(client, build_identity) < 0) {
			logger(LL_ERROR, "Unable to place device into recovery mode from DFU mode\n");
			if (client->tss)
				plist_free(client->tss);
			return -2;
		}
	} else if (client->mode == MODE_RECOVERY) {
		// device is in recovery mode
		if ((client->build_major > 8) && !(client->flags & FLAG_CUSTOM)) {
			if (!client->image4supported) {
				/* send ApTicket */
				if (recovery_send_ticket(client) < 0) {
					logger(LL_ERROR, "Unable to send APTicket\n");
					return -2;
				}
			}
		}

		mutex_lock(&client->device_event_mutex);

		/* now we load the iBEC */
		if (recovery_send_ibec(client, build_identity) < 0) {
			mutex_unlock(&client->device_event_mutex);
			logger(LL_ERROR, "Unable to send iBEC\n");
			return -2;
		}
		recovery_client_free(client);

		logger(LL_DEBUG, "Waiting for device to disconnect...\n");
		cond_wait_timeout(&client->device_event_cond, &client->device_event_mutex, 60000);
		if (client->mode != MODE_UNKNOWN || (client->flags & FLAG_QUIT)) {
			mutex_unlock(&client->device_event_mutex);

			if (!(client->flags & FLAG_QUIT)) {
				logger(LL_ERROR, "Device did not disconnect. Possibly invalid iBEC. Reset device and try again.\n");
			}
			return -2;
		}
		recovery_client_free(client);
		logger(LL_DEBUG, "Waiting for device to reconnect in recovery mode...\n");
		cond_wait_timeout(&client->device_event_cond, &client->device_event_mutex, 60000);
		if (client->mode != MODE_RECOVERY || (client->flags & FLAG_QUIT)) {
			mutex_unlock(&client->device_event_mutex);
			if (!(client->flags & FLAG_QUIT)) {
				logger(LL_ERROR, "Device did not reconnect in recovery mode. Possibly invalid iBEC. Reset device and try again.\n");
			}
			return -2;
		}
		mutex_unlock(&client->device_event_mutex);
	}
	idevicerestore_progress(client, RESTORE_STEP_PREPARE, 0.5);
	if (client->flags & FLAG_QUIT) {
		return -1;
	}

	if (!client->image4supported && (client->build_major > 8)) {
		// we need another tss request with nonce.
		unsigned char* nonce = NULL;
		unsigned int nonce_size = 0;
		int nonce_changed = 0;
		if (get_ap_nonce(client, &nonce, &nonce_size) < 0) {
			logger(LL_ERROR, "Unable to get nonce from device!\n");
			recovery_send_reset(client);
			return -2;
		}

		if (!client->nonce || (nonce_size != client->nonce_size) || (memcmp(nonce, client->nonce, nonce_size) != 0)) {
			nonce_changed = 1;
			if (client->nonce) {
				free(client->nonce);
			}
			client->nonce = nonce;
			client->nonce_size = nonce_size;
		} else {
			free(nonce);
		}

		if (nonce_changed && !(client->flags & FLAG_CUSTOM)) {
			// Welcome iOS5. We have to re-request the TSS with our nonce.
			plist_free(client->tss);
			if (get_tss_response(client, build_identity, &client->tss) < 0) {
				logger(LL_ERROR, "Unable to get SHSH blobs for this device\n");
				return -1;
			}
			if (!client->tss) {
				logger(LL_ERROR, "can't continue without TSS\n");
				return -1;
			}
			fixup_tss(client->tss);
		}
	}
	idevicerestore_progress(client, RESTORE_STEP_PREPARE, 0.7);
	if (client->flags & FLAG_QUIT) {
		return -1;
	}

	// now finally do the magic to put the device into restore mode
	if (client->mode == MODE_RECOVERY) {
#ifdef HAVE_TURDUS_MERULA
		if ((client->flags & FLAG_DOWNGRADE) && is_arm64_soc(client->cpid)) {
			if (
				(client->flags & FLAG_TETHERED) ||
				((client->flags & (FLAG_LOAD_BSEP_SHC | FLAG_FETCH_BSEP_PTE)) == (FLAG_LOAD_BSEP_SHC | FLAG_FETCH_BSEP_PTE))
				)
			{
				{
					// extract sep im4p
					char* sep_path = NULL;
					if (build_identity_has_component(build_identity, "SEP") && build_identity_get_component_path(build_identity, "SEP", &sep_path) == 0) {
						if (extract_component(client->ipsw, sep_path, &client->sep.im4p.data, &client->sep.im4p.length) < 0) {
							logger(LL_ERROR, "Unable to extract component: %s\n", "SEP");
							if (sep_path) {
								free(sep_path);
							}
							return -1;
						}
						if (!client->sep.im4p.data) {
							if (sep_path) {
								free(sep_path);
							}
							logger(LL_ERROR, "Unable to extract component: %s\n", "SEP");
							return -1;
						}
						// save SEP.im4p for tethered
						if (client->flags & FLAG_TETHERED) {
							char zfn[1024];
							if (client->cache_dir) {
								strcpy(zfn, client->cache_dir);
								strcat(zfn, "/image4");
							}
							else {
								strcpy(zfn, "image4");
							}
							mkdir_with_parents(zfn, 0755);
							snprintf(&zfn[0] + strlen(zfn), sizeof(zfn) - strlen(zfn), "/%" PRIu64 "-%s-%s-SEP.im4p", client->ecid, client->device->product_type, client->version);
							FILE *zf = fopen(zfn, "wb");
							if (!zf) {
								logger(LL_ERROR, "Opening %s\n", zfn);
								free(client->sep.im4p.data);
								if (sep_path) {
									free(sep_path);
								}
								return -1;
							}
							fwrite(client->sep.im4p.data, client->sep.im4p.length, 1, zf);
							fflush(zf);
							fclose(zf);
							logger(LL_INFO, "SEP im4p saved to '%s'\n", zfn);
						}
						if (sep_path) {
							free(sep_path);
						}
					}
					else {
						logger(LL_ERROR, "Unable to extract component: %s\n", "SEP");
						if (sep_path) {
							free(sep_path);
						}
						return -1;
					}
				}
				
				{
					// boot_tz0 race is possible even without a valid SEP image
					if (!client->rsep.data || !client->rsep.identity) {
						logger(LL_ERROR, "Could not find information about RestoreSEP\n");
						return -1;
					}
					if (force_get_tss_response(client, client->rsep.identity, &client->rsep.tss) < 0) {
						logger(LL_ERROR, "Unable to get latest SHSH\n");
						return -1;
					}
					if (personalize_component(client, "RestoreSEP", client->rsep.data, client->rsep.length, client->rsep.tss, &client->sep.img4.data, &client->sep.img4.length) < 0) {
						logger(LL_ERROR, "Unable to get personalized component: %s\n", "RestoreSEP");
						return -1;
					}
					if (client->flags & FLAG_TETHERED) {
						// save it
						uint8_t* cached_sep = NULL;
						size_t cached_sep_len = 0;
						if (personalize_component(client, "SEPTethered", client->rsep.data, client->rsep.length, client->rsep.tss, (void **)&cached_sep, &cached_sep_len) < 0) {
							logger(LL_ERROR, "Unable to get personalized component: %s\n", "SEP");
							return -1;
						}
						
						if (cached_sep) {
							char zfn[1024];
							if (client->cache_dir) {
								strcpy(zfn, client->cache_dir);
								strcat(zfn, "/image4");
							}
							else {
								strcpy(zfn, "image4");
							}
							mkdir_with_parents(zfn, 0755);
							snprintf(&zfn[0] + strlen(zfn), sizeof(zfn) - strlen(zfn), "/%" PRIu64 "-%s-signed-SEP.img4", client->ecid, client->device->product_type);
							FILE *zf = fopen(zfn, "wb");
							if (!zf) {
								logger(LL_ERROR, "Opening %s\n", zfn);
								free(cached_sep);
								return -1;
							}
							fwrite(cached_sep, cached_sep_len, 1, zf);
							fflush(zf);
							fclose(zf);
							logger(LL_INFO, "SEP img4 saved to '%s'\n", zfn);
							
							free(cached_sep);
							cached_sep = NULL;
							cached_sep_len = 0;
						}
						else {
							logger(LL_ERROR, "Unable to get cached component: %s\n", "SEP");
							return -1;
						}
					}
				}
			}
		}
#endif
		if (recovery_enter_restore(client, build_identity) < 0) {
			logger(LL_ERROR, "Unable to place device into restore mode\n");
			if (client->tss)
				plist_free(client->tss);
			return -2;
		}
		recovery_client_free(client);
	}
	idevicerestore_progress(client, RESTORE_STEP_PREPARE, 0.9);

	if (client->mode != MODE_RESTORE) {
		mutex_lock(&client->device_event_mutex);
		logger(LL_INFO, "Waiting for device to enter restore mode...\n");
		cond_wait_timeout(&client->device_event_cond, &client->device_event_mutex, 100000000);
#ifdef HAVE_TURDUS_MERULA
		if ((client->flags & FLAG_DOWNGRADE) && is_arm64_soc(client->cpid)) {
			plist_t my_tss = NULL;
			// allocate image4 manifest
			if (
				(client->flags & FLAG_TETHERED) ||
				((client->flags & (FLAG_LOAD_BSEP_SHC | FLAG_FETCH_BSEP_PTE)) == (FLAG_LOAD_BSEP_SHC | FLAG_FETCH_BSEP_PTE))
				)
			{
				if (!client->rsep.tss) {
					logger(LL_ERROR, "no RestoreSEP shsh buffer\n");
					return -1;
				}
				my_tss = client->rsep.tss;
			}
			else if (
					 !((client->flags & FLAG_FETCH_BSEP_SHC) == FLAG_FETCH_BSEP_SHC) &&
					 !((client->flags & FLAG_LOAD_BSEP_SHC | FLAG_FETCH_BSEP_PTE) == FLAG_FETCH_BSEP_PTE)
					 )
			{
				// use cached blob
				if (!client->local_shsh) {
					logger(LL_ERROR, "no local shsh buffer\n");
					return -1;
				}
				my_tss = client->local_shsh;
			}
			
			if (my_tss) {
				plist_t apimg4ticket_tss = plist_dict_get_item(my_tss, "ApImg4Ticket");
				if (apimg4ticket_tss) {
					uint64_t im4m_length = 0;
					plist_get_data_val(apimg4ticket_tss, (char**)&client->sep.im4m.data, &im4m_length);
					client->sep.im4m.length = (size_t)im4m_length;
				}
				if (!client->sep.im4m.data) {
					logger(LL_ERROR, "no img4 manifest\n");
					return -1;
				}
				
				if (have_arm64_single_stage_iboot(client->cpid)) {
					unsigned char tsha384[SHA384_DIGEST_LENGTH];
					memset(tsha384, 0, SHA384_DIGEST_LENGTH);
					sha384_context sha384ctx;
					sha384_init(&sha384ctx);
					sha384_update(&sha384ctx, client->sep.im4m.data, client->sep.im4m.length);
					sha384_final(&sha384ctx, tsha384);
					client->sep.mhash.length = SHA384_DIGEST_LENGTH;
					client->sep.mhash.data = malloc(client->sep.mhash.length);
					if (!client->sep.mhash.data) {
						logger(LL_ERROR, "malloc failed\n");
						return -1;
					}
					memset(client->sep.mhash.data, 0, client->sep.mhash.length);
					memcpy(client->sep.mhash.data, tsha384, SHA384_DIGEST_LENGTH);
				}
				else if (have_arm64_second_stage_iboot(client->cpid)) {
					unsigned char tsha1[SHA1_DIGEST_LENGTH];
					memset(tsha1, 0, SHA1_DIGEST_LENGTH);
					sha1_context sha1ctx;
					sha1_init(&sha1ctx);
					sha1_update(&sha1ctx, client->sep.im4m.data, client->sep.im4m.length);
					sha1_final(&sha1ctx, tsha1);
					client->sep.mhash.length = SHA1_DIGEST_LENGTH;
					client->sep.mhash.data = malloc(client->sep.mhash.length);
					if (!client->sep.mhash.data) {
						logger(LL_ERROR, "malloc failed\n");
						return -1;
					}
					memset(client->sep.mhash.data, 0, client->sep.mhash.length);
					memcpy(client->sep.mhash.data, tsha1, SHA1_DIGEST_LENGTH);
				}
				else {
					logger(LL_ERROR, "Found unknown device\n");
					return -1;
				}
				if (!client->sep.mhash.data) {
					logger(LL_ERROR, "no img4 manifest hash\n");
					return -1;
				}
				
				uint8_t* _manifest_hash = (uint8_t*)client->sep.mhash.data;
				fprintf(stderr, "img4 manifest hash: ");
				for (int i = 0; i < client->sep.mhash.length; i++) {
					fprintf(stderr, "%02x", _manifest_hash[i]);
				}
				fprintf(stderr, "\n");
			}
			
			if (client->mode == MODE_DFU) {
				if (dfu_get_yolo_checkra1n(client) == 0) {
					logger(LL_INFO, "Device entered yolo (checkra1n) DFU mode.\n");
					
					// send pongo
					if (send_pongo_image(client) != 0) {
						mutex_unlock(&client->device_event_mutex);
						if (!(client->flags & FLAG_QUIT)) {
							logger(LL_ERROR, "Failed to upload pongo image\n");
						}
						return -1;
					}
					
					logger(LL_INFO, "Waiting for device to disconnect...\n");
					cond_wait_timeout(&client->device_event_cond, &client->device_event_mutex, 1000000);
					if (client->mode != MODE_UNKNOWN || (client->flags & FLAG_QUIT)) {
						mutex_unlock(&client->device_event_mutex);
						if (!(client->flags & FLAG_QUIT)) {
							logger(LL_ERROR, "Device did not disconnect. Reset device and try again.\n");
						}
						return -1;
					}
					
					logger(LL_INFO, "Waiting for device to enter pongo mode...\n");
					cond_wait_timeout(&client->device_event_cond, &client->device_event_mutex, 500000000);
				}
			}
			
			if (client->mode == MODE_PONGO) {
				logger(LL_INFO, "Found pongo mode\n");
				if (client->dfu == NULL) {
					if (dfu_client_new(client) < 0) {
						mutex_unlock(&client->device_event_mutex);
						if (!(client->flags & FLAG_QUIT)) {
							logger(LL_ERROR, "Failed to create client\n");
						}
						return -1;
					}
				}
				
				int is_pongo_only = 0;
				int is_tethered = 0;
				unsigned int boot_delay = 0;
				if (client->flags & FLAG_FETCH_BSEP) {
					is_pongo_only = 1;
				}
				if (client->flags & FLAG_TETHERED) {
					is_tethered = 1;
				}
				if (client->device->product_type && strncmp(client->device->product_type, "AppleTV", 7) == 0) {
					boot_delay = 10;
				}
				if (pongo_shell(client, client->device, &client->dfu->client, is_pongo_only, is_tethered, boot_delay)) {
					mutex_unlock(&client->device_event_mutex);
					if (!(client->flags & FLAG_QUIT)) {
						logger(LL_ERROR, "Failed to execute pongo shell\n");
					}
					return -1;
				}
				
				if (client->flags & FLAG_FETCH_BSEP) {
					mutex_unlock(&client->device_event_mutex);
					return 0;
				}
				
				logger(LL_INFO, "Waiting for device to disconnect...\n");
				cond_wait_timeout(&client->device_event_cond, &client->device_event_mutex, 1000000);
				if (client->mode != MODE_UNKNOWN || (client->flags & FLAG_QUIT)) {
					mutex_unlock(&client->device_event_mutex);
					if (!(client->flags & FLAG_QUIT)) {
						logger(LL_ERROR, "Device did not disconnect. Reset device and try again.\n");
					}
					return -1;
				}
				
				logger(LL_INFO, "Waiting for device to enter restore mode...\n");
				cond_wait_timeout(&client->device_event_cond, &client->device_event_mutex, 500000000);
			}
		}
#endif
		if (client->mode != MODE_RESTORE || (client->flags & FLAG_QUIT)) {
			mutex_unlock(&client->device_event_mutex);
			logger(LL_ERROR, "Device failed to enter restore mode.\n");
			if (client->mode == MODE_UNKNOWN) {
				logger(LL_ERROR, "Make sure that usbmuxd is running.\n");
			} else if (client->mode == MODE_RECOVERY || client->mode == MODE_DFU) {
				logger(LL_ERROR, "Device reconnected in %s mode, most likely image personalization failed.\n", client->mode->string);
			}
			return -1;
		}
		mutex_unlock(&client->device_event_mutex);
	}

	// device is finally in restore mode, let's do this
	if (client->mode == MODE_RESTORE) {
		if ((client->flags & FLAG_NO_RESTORE) != 0) {
			logger(LL_INFO, "Device is now in restore mode. Exiting as requested.\n");
			return 0;
		}
		client->ignore_device_add_events = 1;
		logger(LL_INFO, "About to restore device... \n");
		result = restore_device(client, build_identity);
		if (result < 0) {
			logger(LL_ERROR, "Unable to restore device\n");
			return result;
		}
	}

	/* special handling of older AppleTVs as they enter Recovery mode on boot when plugged in to USB */
	if ((strncmp(client->device->product_type, "AppleTV", 7) == 0) && (client->device->product_type[7] < '5')) {
		if (recovery_client_new(client) == 0) {
			if (recovery_set_autoboot(client, 1) == 0) {
				recovery_send_reset(client);
			} else {
				logger(LL_ERROR, "Setting auto-boot failed?!\n");
			}
		} else {
			logger(LL_ERROR, "Could not connect to device in recovery mode.\n");
		}
	}

	if (result == 0) {
		logger(LL_INFO, "DONE\n");
		idevicerestore_progress(client, RESTORE_NUM_STEPS-1, 1.0);
	} else {
		logger(LL_INFO, "RESTORE FAILED\n");
	}

	if (build_identity_needs_free)
		plist_free(build_identity);

	return result;
}

struct idevicerestore_client_t* idevicerestore_client_new(void)
{
	struct idevicerestore_client_t* client = (struct idevicerestore_client_t*) malloc(sizeof(struct idevicerestore_client_t));
	if (client == NULL) {
		logger(LL_ERROR, "Out of memory\n");
		return NULL;
	}
	memset(client, '\0', sizeof(struct idevicerestore_client_t));
	client->mode = MODE_UNKNOWN;
	mutex_init(&client->device_event_mutex);
	cond_init(&client->device_event_cond);
	return client;
}

void idevicerestore_client_free(struct idevicerestore_client_t* client)
{
	if (!client) {
		return;
	}

	if (client->irecv_e_ctx) {
		irecv_device_event_unsubscribe(client->irecv_e_ctx);
	}
	if (client->idevice_e_ctx) {
		idevice_event_unsubscribe();
	}
	cond_destroy(&client->device_event_cond);
	mutex_destroy(&client->device_event_mutex);

	if (client->tss_url) {
		free(client->tss_url);
	}
	if (client->version_data) {
		plist_free(client->version_data);
	}
	if (client->nonce) {
		free(client->nonce);
	}
	if (client->udid) {
		free(client->udid);
	}
	if (client->srnm) {
		free(client->srnm);
	}
	if (client->ipsw) {
		ipsw_close(client->ipsw);
	}
	if (client->filesystem) {
		if (client->delete_fs) {
			unlink(client->filesystem);
		}
		free(client->filesystem);
	}
	free(client->version);
	free(client->build);
	free(client->device_version);
	free(client->device_build);
	if (client->restore_boot_args) {
		free(client->restore_boot_args);
	}
	if (client->cache_dir) {
		free(client->cache_dir);
	}
	if (client->root_ticket) {
		free(client->root_ticket);
	}
	if (client->build_manifest) {
		plist_free(client->build_manifest);
	}
	if (client->firmware_preflight_info) {
		plist_free(client->firmware_preflight_info);
	}
	if (client->preflight_info) {
		plist_free(client->preflight_info);
	}
#ifdef HAVE_TURDUS_MERULA
	if (client->bbfw.data) {
		free(client->bbfw.data);
	}
	if (client->sefw.data) {
		free(client->sefw.data);
	}
	if (client->rsep.data) {
		free(client->rsep.data);
	}
	if (client->bbfw.manifest) {
		plist_free(client->bbfw.manifest);
	}
	if (client->sefw.manifest) {
		plist_free(client->sefw.manifest);
	}
	if (client->rsep.manifest) {
		plist_free(client->rsep.manifest);
	}
	if (client->base.manifest) {
		plist_free(client->base.manifest);
	}
	if (client->bbfw.variant) {
		free(client->bbfw.variant);
	}
	if (client->sefw.variant) {
		free(client->sefw.variant);
	}
	if (client->rsep.variant) {
		free(client->rsep.variant);
	}
	if (client->base.variant) {
		free(client->base.variant);
	}
	if (client->bbfw.alternative_hwmodel) {
		free(client->bbfw.alternative_hwmodel);
	}
	if (client->bbfw.tss) {
		plist_free(client->bbfw.tss);
	}
	if (client->sefw.tss) {
		plist_free(client->sefw.tss);
	}
	if (client->rsep.tss) {
		plist_free(client->rsep.tss);
	}
	if (client->base.tss) {
		plist_free(client->base.tss);
	}
	if (client->t_LLB.im4p.data) {
		free(client->t_LLB.im4p.data);
	}
	if (client->t_AppleLogo.im4p.data) {
		free(client->t_AppleLogo.im4p.data);
	}
	if (client->t_BatteryCharging0.im4p.data) {
		free(client->t_BatteryCharging0.im4p.data);
	}
	if (client->t_BatteryCharging1.im4p.data) {
		free(client->t_BatteryCharging1.im4p.data);
	}
	if (client->t_BatteryFull.im4p.data) {
		free(client->t_BatteryFull.im4p.data);
	}
	if (client->t_BatteryLow0.im4p.data) {
		free(client->t_BatteryLow0.im4p.data);
	}
	if (client->t_BatteryLow1.im4p.data) {
		free(client->t_BatteryLow1.im4p.data);
	}
	if (client->t_BatteryPlugin.im4p.data) {
		free(client->t_BatteryPlugin.im4p.data);
	}
	if (client->t_RecoveryMode.im4p.data) {
		free(client->t_RecoveryMode.im4p.data);
	}
	if (client->t_iBoot.im4p.data) {
		free(client->t_iBoot.im4p.data);
	}
	if (client->local_shsh) {
		plist_free(client->local_shsh);
	}
	if (ap_shsh_path) {
		free(ap_shsh_path);
	}
	if (client->cryptex1_nonce_seed) {
		free(client->cryptex1_nonce_seed);
	}
	if (client->sep.im4p.data) {
		free(client->sep.im4p.data);
	}
	if (client->sep.img4.data) {
		free(client->sep.img4.data);
	}
	if (client->sep.im4m.data) {
		free(client->sep.im4m.data);
	}
	if (client->sep.mhash.data) {
		free(client->sep.mhash.data);
	}
	if (client->sep_shellcode_block) {
		free(client->sep_shellcode_block);
	}
#endif
	free(client->restore_variant);
	free(client);
}

void idevicerestore_set_ecid(struct idevicerestore_client_t* client, uint64_t ecid)
{
	if (!client)
		return;
	client->ecid = ecid;
}

void idevicerestore_set_udid(struct idevicerestore_client_t* client, const char* udid)
{
	if (!client)
		return;
	if (client->udid) {
		free(client->udid);
		client->udid = NULL;
	}
	if (udid) {
		client->udid = strdup(udid);
	}
}

void idevicerestore_set_flags(struct idevicerestore_client_t* client, int flags)
{
	if (!client)
		return;
	client->flags = flags;
}

void idevicerestore_set_ipsw(struct idevicerestore_client_t* client, const char* path)
{
	if (!client)
		return;
	if (client->ipsw) {
		ipsw_close(client->ipsw);
		client->ipsw = NULL;
	}
	if (path) {
		client->ipsw = ipsw_open(path);
	}
}

void idevicerestore_set_cache_path(struct idevicerestore_client_t* client, const char* path)
{
	if (!client)
		return;
	if (client->cache_dir) {
		free(client->cache_dir);
		client->cache_dir = NULL;
	}
	if (path) {
		client->cache_dir = strdup(path);
	}
}

void idevicerestore_set_progress_callback(struct idevicerestore_client_t* client, idevicerestore_progress_cb_t cbfunc, void* userdata)
{
	if (!client)
		return;
	client->progress_cb = cbfunc;
	client->progress_cb_data = userdata;
}

#ifndef IDEVICERESTORE_NOMAIN
static struct idevicerestore_client_t* idevicerestore_client = NULL;

static void handle_signal(int sig)
{
	if (idevicerestore_client) {
		idevicerestore_client->flags |= FLAG_QUIT;
		global_quit_flag++;
		ipsw_cancel();
	}
}

void plain_progress_cb(int step, double step_progress, void* userdata)
{
	printf("progress: %u %f\n", step, step_progress);
	fflush(stdout);
}

static void plain_progress_func(struct progress_info_entry** progress_info, int count)
{
	int i = 0;
	for (i = 0; i < count; i++) {
		if (!progress_info[i]) continue;
		printf("%s: %5.1f\n", progress_info[i]->label, progress_info[i]->progress);
		fflush(stdout);
	}
}

static void tty_print(enum loglevel level, const char* fmt, va_list ap)
{
	switch (level) {
		case 0:
			cprintf(FG_RED STYLE_BRIGHT);
			break;
		case 1:
			cprintf(FG_YELLOW STYLE_BRIGHT);
			break;
		case 2:
			cprintf(STYLE_BRIGHT);
			break;
		default:
			break;
	}

	cvfprintf(stdout, fmt, ap);

	cprintf(COLOR_RESET);
}

int main(int argc, char* argv[])
{
	int opt = 0;
	int optindex = 0;
	char* ipsw = NULL;
	int ipsw_info = 0;
	int result = 0;
	const char* logfile = NULL;

	logger_set_print_func(tty_print);

	struct idevicerestore_client_t* client = idevicerestore_client_new();
	if (client == NULL) {
		logger(LL_ERROR, "Could not create idevicerestore client\n");
		return EXIT_FAILURE;
	}

	idevicerestore_client = client;

#ifdef HAVE_TURDUS_MERULA
	client->disable_serial_output = 1;
#endif

#ifdef WIN32
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
	signal(SIGABRT, handle_signal);
#else
	struct sigaction sa;
	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_handler = handle_signal;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);
#endif

	if (!isatty(fileno(stdin)) || !isatty(fileno(stdout))) {
		client->flags &= ~FLAG_INTERACTIVE;
	} else {
		client->flags |= FLAG_INTERACTIVE;
	}

#ifdef HAVE_LIMERA1N
#define P_FLAG "p"
#else
#define P_FLAG ""
#endif

#ifdef HAVE_TURDUS_MERULA
#define TURDUS_MERULA_FLAG "wo"
#else
#define TURDUS_MERULA_FLAG ""
#endif

	while ((opt = getopt_long(argc, argv, "dhces:xtli:u:nC:kyPRT:zv" P_FLAG TURDUS_MERULA_FLAG, longopts, &optindex)) > 0) {
		switch (opt) {
		case 'h':
			usage(argc, argv, 0);
			return EXIT_SUCCESS;

		case 'd':
			client->flags |= FLAG_DEBUG;
			client->debug_level++;
			if (client->debug_level > 0) {
				log_level = LL_DEBUG;
			}
			break;

		case 'e':
			client->flags |= FLAG_ERASE;
			break;

		case 'c':
			client->flags |= FLAG_CUSTOM;
			break;

		case 's': {
			if (!*optarg) {
				logger(LL_ERROR, "URL argument for --server must not be empty!\n");
				usage(argc, argv, 1);
				return EXIT_FAILURE;
			}
			char *baseurl = NULL;
			if (!strncmp(optarg, "http://", 7) && (strlen(optarg) > 7) && (optarg[7] != '/')) {
				baseurl = optarg+7;
			} else if (!strncmp(optarg, "https://", 8) && (strlen(optarg) > 8) && (optarg[8] != '/')) {
				baseurl = optarg+8;
			}
			if (baseurl) {
				char *p = strchr(baseurl, '/');
				if (!p || *(p+1) == '\0') {
					// no path component, add default path
					const char default_path[] = "/TSS/controller?action=2";
					size_t usize = strlen(optarg)+sizeof(default_path);
					char* newurl = malloc(usize);
					snprintf(newurl, usize, "%s%s", optarg, (p) ? default_path+1 : default_path);
					client->tss_url = newurl;
				} else {
					client->tss_url = strdup(optarg);
				}
			} else {
				logger(LL_ERROR, "URL argument for --server is invalid, must start with http:// or https://\n");
				usage(argc, argv, 1);
				return EXIT_FAILURE;
			}
		}
			break;

		case 'x':
			client->flags |= FLAG_EXCLUDE;
			break;

		case 'l':
			client->flags |= FLAG_LATEST;
			break;

		case 'i':
			if (optarg) {
				char* tail = NULL;
				client->ecid = strtoull(optarg, &tail, 0);
				if (tail && (tail[0] != '\0')) {
					client->ecid = 0;
				}
				if (client->ecid == 0) {
					logger(LL_ERROR, "Could not parse ECID from '%s'\n", optarg);
					return EXIT_FAILURE;
				}
			}
			break;

		case 'u':
			if (!*optarg) {
				logger(LL_ERROR, "UDID must not be empty!\n");
				usage(argc, argv, 1);
				return EXIT_FAILURE;
			}
			client->udid = strdup(optarg);
			break;

		case 't':
			client->flags |= FLAG_SHSHONLY;
			break;

		case 'k':
			client->flags |= FLAG_KEEP_PERS;
			break;

#ifdef HAVE_LIMERA1N
		case 'p':
			client->flags |= FLAG_PWN;
			break;
#endif

		case 'n':
			client->flags |= FLAG_NOACTION;
			break;

		case 'C':
			client->cache_dir = strdup(optarg);
			break;

		case 'y':
			client->flags &= ~FLAG_INTERACTIVE;
			break;

		case 'P':
			idevicerestore_set_progress_callback(client, plain_progress_cb, NULL);
			set_update_progress_func(plain_progress_func);
			set_progress_granularity(0.01); // 1% granularity
			break;

		case 'R':
			client->flags |= FLAG_ALLOW_RESTORE_MODE;
			break;

		case 'z':
			client->flags |= FLAG_NO_RESTORE;
			break;

		case 'v':
#ifdef HAVE_TURDUS_MERULA
                printf("turdus_merula[%s] version: %s\n", PACKAGE_NAME, PACKAGE_VERSION);
                printf("Library version\n");
                printf("- %s: %s\n", "libirecovery", irecv_version());
                printf("- %s: %s\n", "libtatsu", libtatsu_version());
                printf("- %s: %s\n", "libusbmuxd", libusbmuxd_version());
                printf("- %s: %s\n", "libplist", libplist_version());
                printf("- %s: %s\n", "libimobiledevice_glue", libimobiledevice_glue_version());
                printf("- %s: %s\n", "libimobiledevice", libimobiledevice_version());
                printf("- %s: %s\n", "libfragmentzip", fragmentzip_version());
                printf("- %s: %s\n", "libzip", zip_libzip_version());
                printf("- %s: %s\n", "libcurl", curl_version());
#else
			printf("%s %s (libirecovery %s, libtatsu %s)\n", PACKAGE_NAME, PACKAGE_VERSION, irecv_version(), libtatsu_version());
#endif
			return EXIT_SUCCESS;

		case 'T': {
			size_t root_ticket_len = 0;
			unsigned char* root_ticket = NULL;
			if (read_file(optarg, (void**)&root_ticket, &root_ticket_len) != 0) {
				return EXIT_FAILURE;
			}
			client->root_ticket = root_ticket;
			client->root_ticket_len = (int)root_ticket_len;
			logger(LL_INFO, "Using ApTicket found at %s length %u\n", optarg, client->root_ticket_len);
			break;
		}

		case 'I':
			ipsw_info = 1;
			break;

		case 1:
			client->flags |= FLAG_IGNORE_ERRORS;
			break;

		case 2:
			free(client->restore_variant);
			client->restore_variant = strdup(optarg);
			break;

		case 3:
			if (!*optarg) {
				logger(LL_ERROR, "logfile must not be empty!\n");
				usage(argc, argv, 1);
				return EXIT_FAILURE;
			}
			logfile = optarg;
			break;

#ifdef HAVE_TURDUS_MERULA
			case 'w':
				client->flags |= FLAG_ERASE | FLAG_DOWNGRADE;
				break;
				
			case 'o':
				client->flags |= FLAG_ERASE | FLAG_DOWNGRADE | FLAG_TETHERED;
				break;
				
			case 11:
				if (!*optarg) {
					logger(LL_ERROR, "MODEL argument for --alternative-hwmodel must not be empty!\n");
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				free((void*)client->bbfw.alternative_hwmodel);
				client->bbfw.alternative_hwmodel = strdup(optarg);
				break;
				
			case 12:
				if (!*optarg) {
					logger(LL_ERROR, "PATH argument for --bbfw must not be empty!\n");
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				if (load_firmware_component_data(optarg, &client->bbfw, "bbfw") != 0) {
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				break;
				
			case 15:
				if (!*optarg) {
					logger(LL_ERROR, "PATH argument for --sefw must not be empty!\n");
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				if (load_firmware_component_data(optarg, &client->sefw, "sefw") != 0) {
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				break;
				
			case 18:
				if (!*optarg) {
					logger(LL_ERROR, "PATH argument for --rsep must not be empty!\n");
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				if (load_firmware_component_data(optarg, &client->rsep, "rsep") != 0) {
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				break;
				
			case 13:
				if (!*optarg) {
					logger(LL_ERROR, "PATH argument for --bbfw-manifest must not be empty!\n");
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				if (load_firmware_component_plist(optarg, &client->bbfw, "bbfw") != 0) {
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				break;
				
			case 16:
				if (!*optarg) {
					logger(LL_ERROR, "PATH argument for --sefw-manifest must not be empty!\n");
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				if (load_firmware_component_plist(optarg, &client->sefw, "sefw") != 0) {
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				break;
				
			case 19:
				if (!*optarg) {
					logger(LL_ERROR, "PATH argument for --rsep-manifest must not be empty!\n");
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				if (load_firmware_component_plist(optarg, &client->rsep, "rsep") != 0) {
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				break;
				
			case 21:
				if (!*optarg) {
					logger(LL_ERROR, "PATH argument for --base-manifest must not be empty!\n");
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				if (load_firmware_component_plist(optarg, &client->base, "base") != 0) {
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				break;
				
			case 14:
				if (!*optarg) {
					logger(LL_ERROR, "VARIANT argument for --bbfw-variant must not be empty!\n");
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				free(client->bbfw.variant);
				client->bbfw.variant = strdup(optarg);
				break;
				
			case 17:
				if (!*optarg) {
					logger(LL_ERROR, "VARIANT argument for --sefw-variant must not be empty!\n");
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				free(client->sefw.variant);
				client->sefw.variant = strdup(optarg);
				break;
				
			case 20:
				if (!*optarg) {
					logger(LL_ERROR, "VARIANT argument for --rsep-variant must not be empty!\n");
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				free(client->rsep.variant);
				client->rsep.variant = strdup(optarg);
				break;
				
			case 22:
				if (!*optarg) {
					logger(LL_ERROR, "VARIANT argument for --base-variant must not be empty!\n");
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				free(client->base.variant);
				client->base.variant = strdup(optarg);
				break;
			
			case 23:
				if (!*optarg) {
					logger(LL_ERROR, "PATH argument for --load-shsh must not be empty!\n");
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				ap_shsh_path = strdup(optarg);
				client->use_custom_ticket = 1;
				break;
				
			case 24:
				if (!*optarg) {
					logger(LL_ERROR, "PATH argument for --load-shcblock must not be empty!\n");
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				if (client->sep_shellcode_block) {
					logger(LL_ERROR, "Already block loaded\n");
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				if (read_file_safe(optarg, (void**)&client->sep_shellcode_block, &client->sep_shellcode_block_len, 0x400) != 0) {
					return EXIT_FAILURE;
				}
				logger(LL_INFO, "Using SEP shellcode ciphertext block, found at %s length %zu\n", optarg, client->sep_shellcode_block_len);
				client->flags |= FLAG_LOAD_BSEP_SHC;
				break;
				
			case 25:
				if (!*optarg) {
					logger(LL_ERROR, "PATH argument for --load-pteblock must not be empty!\n");
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				if (client->sep_shellcode_block) {
					logger(LL_ERROR, "Already block loaded\n");
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				if (read_file_safe(optarg, (void**)&client->sep_shellcode_block, &client->sep_shellcode_block_len, 0x400) != 0) {
					return EXIT_FAILURE;
				}
				logger(LL_INFO, "Using SEP page table entry ciphertext block, found at %s length %zu\n", optarg, client->sep_shellcode_block_len);
				client->flags |= FLAG_LOAD_BSEP_PTE;
				break;
				
			case 26:
				client->disable_serial_output = 0;
				break;
				
			case 27:
				client->flags |= FLAG_DOWNGRADE;
				client->flags |= FLAG_FETCH_BSEP_SHC;
				break;
				
			case 28:
				client->flags |= FLAG_DOWNGRADE;
				client->flags |= FLAG_FETCH_BSEP_PTE;
				break;
				
			case 29:
				client->flags |= FLAG_ALLOW_UNSUPPORTED;
				break;
				
			case 30:
				print_module_hash("Pongo.bin", Pongo_bin, Pongo_bin_len);
				print_module_hash("cpf", cpf_bin, cpf_bin_len);
				print_module_hash("kpf", kpf_bin, kpf_bin_len);
				print_module_hash("sep_racer", sep_racer_bin, sep_racer_bin_len);
				print_module_hash("overlay.dmg[iPhoneOS]", overlay_iphoneos_bin, overlay_iphoneos_bin_len);
				print_module_hash("overlay.dmg[tvOS]", overlay_tvos_bin, overlay_tvos_bin_len);
				print_module_hash("union.dmg[iPhoneOS]", union_iphoneos_bin, union_iphoneos_bin_len);
				print_module_hash("union.dmg[tvOS]", union_tvos_bin, union_tvos_bin_len);
				return EXIT_SUCCESS;
				
			case 31:
				if (gAPIURL) {
					logger(LL_ERROR, "API URL has already been set!\n");
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				if (!*optarg) {
					logger(LL_ERROR, "URL argument for --api-url must not be empty!\n");
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				char *baseurl = NULL;
				if (!strncmp(optarg, "http://", 7) && (strlen(optarg) > 7) && (optarg[7] != '/')) {
					baseurl = optarg + 7;
				}
				else if (!strncmp(optarg, "https://", 8) && (strlen(optarg) > 8) && (optarg[8] != '/')) {
					baseurl = optarg + 8;
				}
				if (baseurl) {
					gAPIURL = strdup(optarg);
				}
				else {
					logger(LL_ERROR, "URL argument for --api-url is invalid, must start with http:// or https://\n");
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				break;
				
			case 32:
				if (!*optarg) {
					logger(LL_ERROR, "PATH argument for --override-kpf must not be empty!\n");
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				if (gKPF) {
					free(gKPF);
					gKPF = NULL;
					gKPFLength = 0;
				}
				if (read_aligned_file_safe(optarg, (void**)&gKPF, &gKPFLength, 0x400000) != 0) {
					return EXIT_FAILURE;
				}
				logger(LL_INFO, "Loaded custom KPF module, found at %s length %zu\n", optarg, gKPFLength);
				break;
				
			case 33:
				if (!*optarg) {
					logger(LL_ERROR, "PATH argument for --override-cpf must not be empty!\n");
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				if (gCPF) {
					free(gCPF);
					gCPF = NULL;
					gCPFLength = 0;
				}
				if (read_aligned_file_safe(optarg, (void**)&gCPF, &gCPFLength, 0x400000) != 0) {
					return EXIT_FAILURE;
				}
				logger(LL_INFO, "Loaded custom CPF module, found at %s length %zu\n", optarg, gCPFLength);
				break;
				
			case 34:
				if (!*optarg) {
					logger(LL_ERROR, "PATH argument for --override-sep-racer must not be empty!\n");
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				if (gSEPRacer) {
					free(gSEPRacer);
					gSEPRacer = NULL;
					gSEPRacerLength = 0;
				}
				if (read_aligned_file_safe(optarg, (void**)&gSEPRacer, &gSEPRacerLength, 0x400000) != 0) {
					return EXIT_FAILURE;
				}
				logger(LL_INFO, "Loaded custom sep_racer module, found at %s length %zu\n", optarg, gSEPRacerLength);
				break;
				
			case 35:
				if (!*optarg) {
					logger(LL_ERROR, "PATH argument for --override-pongo must not be empty!\n");
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				if (gPongoOS) {
					free(gPongoOS);
					gPongoOS = NULL;
					gPongoOSLength = 0;
				}
				if (read_aligned_file_safe(optarg, (void**)&gPongoOS, &gPongoOSLength, 0x100000) != 0) {
					return EXIT_FAILURE;
				}
				logger(LL_INFO, "Loaded custom Pongo, found at %s length %zu\n", optarg, gPongoOSLength);
				break;
				
			case 36:
				if (!*optarg) {
					logger(LL_ERROR, "PATH argument for --override-ramdisk must not be empty!\n");
					usage(argc, argv, 1);
					return EXIT_FAILURE;
				}
				if (gRAMDisk) {
					free(gRAMDisk);
					gRAMDisk = NULL;
					gRAMDiskLength = 0;
				}
				if (read_aligned_file_safe(optarg, (void**)&gRAMDisk, &gRAMDiskLength, 0x800000) != 0) {
					return EXIT_FAILURE;
				}
				logger(LL_INFO, "Loaded custom overlay ramdisk, found at %s length %zu\n", optarg, gRAMDiskLength);
				break;
#endif

		default:
			usage(argc, argv, 1);
			return EXIT_FAILURE;
		}
	}

	if (ipsw_info) {
		if (argc-optind != 1) {
			logger(LL_ERROR, "--ipsw-info requires an IPSW path.\n");
			usage(argc, argv, 1);
			return EXIT_FAILURE;
		}
		return (ipsw_print_info(*(argv + optind)) == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
	}

	if (((argc-optind) == 1) || (client->flags & FLAG_PWN) || (client->flags & FLAG_LATEST)) {
		argc -= optind;
		argv += optind;

		ipsw = argv[0];
	} else {
		usage(argc, argv, 1);
		return EXIT_FAILURE;
	}

	if ((client->flags & FLAG_LATEST) && (client->flags & FLAG_CUSTOM)) {
		logger(LL_ERROR, "You can't use --custom and --latest options at the same time.\n");
		return EXIT_FAILURE;
	}

	if (!logfile) {
		char logfn[256];
		int64_t timestamp = time(NULL);
		if (client->ecid) {
			snprintf(logfn, sizeof(logfn), "restore_%016" PRIx64 "_%" PRIi64 ".log", client->ecid, timestamp);
		} else if (client->udid) {
			snprintf(logfn, sizeof(logfn), "restore_%s_%" PRIi64 ".log", client->udid, timestamp);
		} else {
			snprintf(logfn, sizeof(logfn), "restore_%" PRIi64 ".log", timestamp);
		}
		logger_set_logfile(logfn);
	} else {
		logger_set_logfile(logfile);
	}

	logger(LL_INFO, "%s %s (libirecovery %s, libtatsu %s)\n", PACKAGE_NAME, PACKAGE_VERSION, irecv_version(), libtatsu_version());

	if (ipsw) {
		// verify if ipsw file exists
		client->ipsw = ipsw_open(ipsw);
		if (!client->ipsw) {
			logger(LL_ERROR, "Firmware file %s cannot be opened.\n", ipsw);
			return -1;
		}
	}

	curl_global_init(CURL_GLOBAL_ALL);

	client->flags |= FLAG_IN_PROGRESS;
	result = idevicerestore_start(client);
	client->flags &= ~FLAG_IN_PROGRESS;

	idevicerestore_client_free(client);

	curl_global_cleanup();

	return (result == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
#endif

irecv_device_t get_irecv_device(struct idevicerestore_client_t *client)
{
	int mode = _MODE_UNKNOWN;

	if (client->mode) {
		mode = client->mode->index;
	}

	switch (mode) {
	case _MODE_RESTORE:
		return restore_get_irecv_device(client);

	case _MODE_NORMAL:
		return normal_get_irecv_device(client);

	case _MODE_DFU:
	case _MODE_PORTDFU:
	case _MODE_RECOVERY:
#ifdef HAVE_TURDUS_MERULA
	case _MODE_PONGO:
#endif
		return dfu_get_irecv_device(client);

	default:
		return NULL;
	}
}

int is_image4_supported(struct idevicerestore_client_t* client)
{
	int res = 0;
	int mode = _MODE_UNKNOWN;

	if (client->mode) {
		mode = client->mode->index;
	}

	switch (mode) {
	case _MODE_NORMAL:
		res = normal_is_image4_supported(client);
		break;
	case _MODE_RESTORE:
		res = restore_is_image4_supported(client);
		break;
	case _MODE_DFU:
		res = dfu_is_image4_supported(client);
		break;
	case _MODE_RECOVERY:
		res = recovery_is_image4_supported(client);
		break;
	default:
		logger(LL_ERROR, "Device is in an invalid state\n");
		return 0;
	}
	return res;
}

int get_ap_nonce(struct idevicerestore_client_t* client, unsigned char** nonce, unsigned int* nonce_size)
{
	int mode = _MODE_UNKNOWN;

	*nonce = NULL;
	*nonce_size = 0;

	if (client->mode) {
		mode = client->mode->index;
	}

	switch (mode) {
	case _MODE_NORMAL:
		logger(LL_INFO, "Getting ApNonce in Normal mode... ");
		if (normal_get_ap_nonce(client, nonce, nonce_size) < 0) {
			logger(LL_INFO, "failed\n");
			return -1;
		}
		break;
	case _MODE_DFU:
		logger(LL_INFO, "Getting ApNonce in DFU mode... ");
		if (dfu_get_ap_nonce(client, nonce, nonce_size) < 0) {
			logger(LL_INFO, "failed\n");
			return -1;
		}
		break;
	case _MODE_RECOVERY:
		logger(LL_INFO, "Getting ApNonce in Recovery mode... ");
		if (recovery_get_ap_nonce(client, nonce, nonce_size) < 0) {
			logger(LL_INFO, "failed\n");
			return -1;
		}
		break;

	default:
		logger(LL_INFO, "Getting ApNonce failed\n");
		logger(LL_ERROR, "Device is in an invalid state\n");
		return -1;
	}

	logger_dump_hex(LL_INFO, *nonce, *nonce_size);

	return 0;
}

int get_sep_nonce(struct idevicerestore_client_t* client, unsigned char** nonce, unsigned int* nonce_size)
{
	int mode = _MODE_UNKNOWN;

	*nonce = NULL;
	*nonce_size = 0;

	if (client->mode) {
		mode = client->mode->index;
	}

	switch (mode) {
	case _MODE_NORMAL:
		logger(LL_INFO, "Getting SepNonce in normal mode... ");
		if (normal_get_sep_nonce(client, nonce, nonce_size) < 0) {
			logger(LL_INFO, "failed\n");
			return -1;
		}
		break;
	case _MODE_DFU:
		logger(LL_INFO, "Getting SepNonce in dfu mode... ");
		if (dfu_get_sep_nonce(client, nonce, nonce_size) < 0) {
			logger(LL_INFO, "failed\n");
			return -1;
		}
		break;
	case _MODE_RECOVERY:
		logger(LL_INFO, "Getting SepNonce in recovery mode... ");
		if (recovery_get_sep_nonce(client, nonce, nonce_size) < 0) {
			logger(LL_INFO, "failed\n");
			return -1;
		}
		break;

	default:
		logger(LL_INFO, "Getting SepNonce failed\n");
		logger(LL_ERROR, "Device is in an invalid state\n");
		return -1;
	}

	logger_dump_hex(LL_INFO, *nonce, *nonce_size);

	return 0;
}

plist_t build_manifest_get_build_identity_for_model_with_variant(plist_t build_manifest, const char *hardware_model, const char *variant, int exact)
{
	plist_t build_identities_array = plist_dict_get_item(build_manifest, "BuildIdentities");
	if (!build_identities_array || plist_get_node_type(build_identities_array) != PLIST_ARRAY) {
		logger(LL_ERROR, "Unable to find build identities node\n");
		return NULL;
	}

	uint32_t i;
	for (i = 0; i < plist_array_get_size(build_identities_array); i++) {
		plist_t ident = plist_array_get_item(build_identities_array, i);
		if (!ident || plist_get_node_type(ident) != PLIST_DICT) {
			continue;
		}
		plist_t info_dict = plist_dict_get_item(ident, "Info");
		if (!info_dict || plist_get_node_type(ident) != PLIST_DICT) {
			continue;
		}
		plist_t devclass = plist_dict_get_item(info_dict, "DeviceClass");
		if (!devclass || plist_get_node_type(devclass) != PLIST_STRING) {
			continue;
		}
		const char *str = plist_get_string_ptr(devclass, NULL);
		if (strcasecmp(str, hardware_model) != 0) {
			continue;
		}
		if (variant) {
			plist_t rvariant = plist_dict_get_item(info_dict, "Variant");
			if (!rvariant || plist_get_node_type(rvariant) != PLIST_STRING) {
				continue;
			}
			str = plist_get_string_ptr(rvariant, NULL);
			if (strcmp(str, variant) != 0) {
				/* if it's not a full match, let's try a partial match, but ignore "*Research*" */
				if (!exact && strstr(str, variant) && !strstr(str, "Research")) {
					return ident;
				}
				continue;
			} else {
				return ident;
			}
		} else {
			return ident;
		}
	}

	return NULL;
}

plist_t build_manifest_get_build_identity_for_model(plist_t build_manifest, const char *hardware_model)
{
	return build_manifest_get_build_identity_for_model_with_variant(build_manifest, hardware_model, NULL, 0);
}

int get_preboard_manifest(struct idevicerestore_client_t* client, plist_t build_identity, plist_t* manifest)
{
	plist_t request = NULL;
	*manifest = NULL;

	if (!client->image4supported) {
		return -1;
	}

	/* populate parameters */
	plist_t parameters = plist_new_dict();

	plist_t overrides = plist_new_dict();
	plist_dict_set_item(overrides, "@APTicket", plist_new_bool(1));
	plist_dict_set_item(overrides, "ApProductionMode", plist_new_uint(0));
	plist_dict_set_item(overrides, "ApSecurityDomain", plist_new_uint(1));

	plist_dict_set_item(parameters, "ApProductionMode", plist_new_bool(0));
	plist_dict_set_item(parameters, "ApSecurityMode", plist_new_bool(0));
	plist_dict_set_item(parameters, "ApSupportsImg4", plist_new_bool(1));

	tss_parameters_add_from_manifest(parameters, build_identity, true);

	/* create basic request */
	request = tss_request_new(NULL);
	if (request == NULL) {
		logger(LL_ERROR, "Unable to create TSS request\n");
		plist_free(parameters);
		return -1;
	}

	/* add common tags from manifest */
	if (tss_request_add_common_tags(request, parameters, overrides) < 0) {
		logger(LL_ERROR, "Unable to add common tags\n");
		plist_free(request);
		plist_free(parameters);
		return -1;
	}

	plist_dict_set_item(parameters, "_OnlyFWComponents", plist_new_bool(1));

	/* add tags from manifest */
	if (tss_request_add_ap_tags(request, parameters, NULL) < 0) {
		logger(LL_ERROR, "Unable to add ap tags\n");
		plist_free(request);
		plist_free(parameters);
		return -1;
	}

	plist_t local_manifest = NULL;
	int res = img4_create_local_manifest(request, build_identity, &local_manifest);

	*manifest = local_manifest;

	plist_free(request);
	plist_free(parameters);
	plist_free(overrides);

	return res;
}

int get_tss_response(struct idevicerestore_client_t* client, plist_t build_identity, plist_t* tss)
{
	plist_t request = NULL;
	plist_t response = NULL;
	*tss = NULL;

#ifdef HAVE_TURDUS_MERULA
	uint64_t mask_flag = FLAG_DOWNGRADE | FLAG_CUSTOM;
#else
	uint64_t mask_flag = FLAG_CUSTOM;
#endif
	if ((client->build_major <= 8) || (client->flags & mask_flag)) {
		logger(LL_INFO, "Checking for local shsh\n");

		/* first check for local copy */
		char zfn[1024];
		if (client->version) {
#ifdef HAVE_TURDUS_MERULA
			if (client->local_shsh) {
				*tss = plist_copy(client->local_shsh);
				logger(LL_INFO, "Using cached SHSH\n");
				return 0;
			}
			else if ((client->flags & FLAG_TETHERED) || (client->flags & FLAG_FETCH_BSEP)) {
				if (client->base.tss) {
					*tss = plist_copy(client->base.tss);
					logger(LL_INFO, "Using cached SHSH\n");
					return 0;
				}
				else if (client->base.identity) {
					if (force_get_tss_response(client, client->base.identity, &client->base.tss) < 0) {
						logger(LL_ERROR, "Unable to get latest SHSH\n");
						return -1;
					}
					*tss = plist_copy(client->base.tss);
					logger(LL_INFO, "Using latest SHSH\n");
					return 0;
				}
				else {
					logger(LL_INFO, "No valid build identity\n");
					return 0;
				}
			}
			else
#endif
			if (client->cache_dir) {
				snprintf(zfn, sizeof(zfn), "%s/shsh/%" PRIu64 "-%s-%s.shsh", client->cache_dir, client->ecid, client->device->product_type, client->version);
			} else {
				snprintf(zfn, sizeof(zfn), "shsh/%" PRIu64 "-%s-%s.shsh", client->ecid, client->device->product_type, client->version);
			}
			struct stat fst;
			if (stat(zfn, &fst) == 0) {
				gzFile zf = gzopen(zfn, "rb");
				if (zf) {
					int blen = 0;
					int readsize = 16384;
					int bufsize = readsize;
					char* bin = (char*)malloc(bufsize);
					char* p = bin;
					do {
						int bytes_read = gzread(zf, p, readsize);
						if (bytes_read < 0) {
							logger(LL_ERROR, "Error reading gz compressed data\n");
							exit(EXIT_FAILURE);
						}
						blen += bytes_read;
						if (bytes_read < readsize) {
							if (gzeof(zf)) {
								bufsize += bytes_read;
								break;
							}
						}
						bufsize += readsize;
						bin = realloc(bin, bufsize);
						p = bin + blen;
					} while (!gzeof(zf));
					gzclose(zf);
					if (blen > 0) {
						if (memcmp(bin, "bplist00", 8) == 0) {
							plist_from_bin(bin, blen, tss);
						} else {
							plist_from_xml(bin, blen, tss);
						}
					}
					free(bin);
				}
			} else {
				logger(LL_ERROR, "no local file %s\n", zfn);
			}
		} else {
			logger(LL_ERROR, "No version found?!\n");
		}
	}

	if (*tss) {
		logger(LL_INFO, "Using cached SHSH\n");
		return 0;
	} else {
		logger(LL_INFO, "Trying to fetch new SHSH blob\n");
	}

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
	} else {
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
	} else {
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

			if (plist_dict_get_item(parameters, "BbSNUM")) {
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
		}
		client->firmware_preflight_info = pinfo;
		pinfo = NULL;

		normal_get_preflight_info(client, &pinfo);
		client->preflight_info = pinfo;
	}

	/* send request and grab response */
	response = tss_request_send(request, client->tss_url);
	if (response == NULL) {
		logger(LL_INFO, "ERROR: Unable to send TSS request\n");
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

int get_recoveryos_root_ticket_tss_response(struct idevicerestore_client_t* client, plist_t build_identity, plist_t* tss)
{
	plist_t request = NULL;
	plist_t response = NULL;
	*tss = NULL;

	/* populate parameters */
	plist_t parameters = plist_new_dict();

	/* ApECID */
	plist_dict_set_item(parameters, "ApECID", plist_new_uint(client->ecid));
	plist_dict_set_item(parameters, "Ap,LocalBoot", plist_new_bool(0));

	/* ApNonce */
	if (client->nonce) {
		plist_dict_set_item(parameters, "ApNonce", plist_new_data((const char*)client->nonce, client->nonce_size));
	}
	unsigned char* sep_nonce = NULL;
	unsigned int sep_nonce_size = 0;
	get_sep_nonce(client, &sep_nonce, &sep_nonce_size);

	/* ApSepNonce */
	if (sep_nonce) {
		plist_dict_set_item(parameters, "ApSepNonce", plist_new_data((const char*)sep_nonce, sep_nonce_size));
		free(sep_nonce);
	}

	/* ApProductionMode */
	plist_dict_set_item(parameters, "ApProductionMode", plist_new_bool(1));

	/* ApSecurityMode */
	if (client->image4supported) {
		plist_dict_set_item(parameters, "ApSecurityMode", plist_new_bool(1));
		plist_dict_set_item(parameters, "ApSupportsImg4", plist_new_bool(1));
	} else {
		plist_dict_set_item(parameters, "ApSupportsImg4", plist_new_bool(0));
	}

	tss_parameters_add_from_manifest(parameters, build_identity, true);

	/* create basic request */
	/* Adds @HostPlatformInfo, @VersionInfo, @UUID */
	request = tss_request_new(NULL);
	if (request == NULL) {
		logger(LL_ERROR, "Unable to create TSS request\n");
		plist_free(parameters);
		return -1;
	}

	/* add common tags from manifest */
	/* Adds Ap,OSLongVersion, ApNonce, @ApImg4Ticket */
	if (tss_request_add_ap_img4_tags(request, parameters) < 0) {
		logger(LL_ERROR, "Unable to add AP IMG4 tags to TSS request\n");
		plist_free(request);
		plist_free(parameters);
		return -1;
	}

	/* add AP tags from manifest */
	if (tss_request_add_common_tags(request, parameters, NULL) < 0) {
		logger(LL_ERROR, "Unable to add common tags to TSS request\n");
		plist_free(request);
		plist_free(parameters);
		return -1;
	}

	/* add AP tags from manifest */
	/* Fills digests & co */
	if (tss_request_add_ap_recovery_tags(request, parameters, NULL) < 0) {
		logger(LL_ERROR, "Unable to add common tags to TSS request\n");
		plist_free(request);
		plist_free(parameters);
		return -1;
	}

	/* send request and grab response */
	response = tss_request_send(request, client->tss_url);
	if (response == NULL) {
		logger(LL_INFO, "ERROR: Unable to send TSS request\n");
		plist_free(request);
		plist_free(parameters);
		return -1;
	}
	// request_add_ap_tags

	logger(LL_INFO, "Received SHSH blobs\n");

	plist_free(request);
	plist_free(parameters);

	*tss = response;

	return 0;
}

int get_recovery_os_local_policy_tss_response(
				struct idevicerestore_client_t* client,
				plist_t build_identity,
				plist_t* tss,
				plist_t args)
{
	plist_t request = NULL;
	plist_t response = NULL;
	*tss = NULL;

	/* populate parameters */
	plist_t parameters = plist_new_dict();
	plist_dict_set_item(parameters, "ApECID", plist_new_uint(client->ecid));
	plist_dict_set_item(parameters, "Ap,LocalBoot", plist_new_bool(1));

	plist_dict_set_item(parameters, "ApProductionMode", plist_new_bool(1));
	if (client->image4supported) {
		plist_dict_set_item(parameters, "ApSecurityMode", plist_new_bool(1));
		plist_dict_set_item(parameters, "ApSupportsImg4", plist_new_bool(1));
	} else {
		plist_dict_set_item(parameters, "ApSupportsImg4", plist_new_bool(0));
	}

	tss_parameters_add_from_manifest(parameters, build_identity, true);

	// Add Ap,LocalPolicy
	uint8_t digest[SHA384_DIGEST_LENGTH];
	sha384(lpol_file, lpol_file_length, digest);
	plist_t lpol = plist_new_dict();
	plist_dict_set_item(lpol, "Digest", plist_new_data((char*)digest, SHA384_DIGEST_LENGTH));
	plist_dict_set_item(lpol, "Trusted", plist_new_bool(1));
	plist_dict_set_item(parameters, "Ap,LocalPolicy", lpol);

	plist_dict_copy_data(parameters, args, "Ap,NextStageIM4MHash", NULL);
	plist_dict_copy_data(parameters, args, "Ap,RecoveryOSPolicyNonceHash", NULL);

	plist_t vol_uuid_node = plist_dict_get_item(args, "Ap,VolumeUUID");
	char* vol_uuid_str = NULL;
	plist_get_string_val(vol_uuid_node, &vol_uuid_str);
	unsigned int vuuid[16];
	unsigned char vol_uuid[16];
	if (sscanf(vol_uuid_str, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", &vuuid[0], &vuuid[1], &vuuid[2], &vuuid[3], &vuuid[4], &vuuid[5], &vuuid[6], &vuuid[7], &vuuid[8], &vuuid[9], &vuuid[10], &vuuid[11], &vuuid[12], &vuuid[13], &vuuid[14], &vuuid[15]) != 16) {
		logger(LL_ERROR, "Failed to parse Ap,VolumeUUID (%s)\n", vol_uuid_str);
		free(vol_uuid_str);
		return -1;
	}
	free(vol_uuid_str);
	int i;
	for (i = 0; i < 16; i++) {
		vol_uuid[i] = (unsigned char)vuuid[i];
	}
	plist_dict_set_item(parameters, "Ap,VolumeUUID", plist_new_data((char*)vol_uuid, 16));

	/* create basic request */
	request = tss_request_new(NULL);
	if (request == NULL) {
		logger(LL_ERROR, "Unable to create TSS request\n");
		plist_free(parameters);
		return -1;
	}

	/* add common tags from manifest */
	if (tss_request_add_local_policy_tags(request, parameters) < 0) {
		logger(LL_ERROR, "Unable to add common tags to TSS request\n");
		plist_free(request);
		plist_free(parameters);
		return -1;
	}

	/* send request and grab response */
	response = tss_request_send(request, client->tss_url);
	if (response == NULL) {
		logger(LL_INFO, "ERROR: Unable to send TSS request\n");
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

int get_local_policy_tss_response(struct idevicerestore_client_t* client, plist_t build_identity, plist_t* tss)
{
	plist_t request = NULL;
	plist_t response = NULL;
	*tss = NULL;

	/* populate parameters */
	plist_t parameters = plist_new_dict();
	plist_dict_set_item(parameters, "ApECID", plist_new_uint(client->ecid));
	plist_dict_set_item(parameters, "Ap,LocalBoot", plist_new_bool(0));
	if (client->nonce) {
		plist_dict_set_item(parameters, "ApNonce", plist_new_data((const char*)client->nonce, client->nonce_size));
	}
	unsigned char* sep_nonce = NULL;
	unsigned int sep_nonce_size = 0;
	get_sep_nonce(client, &sep_nonce, &sep_nonce_size);

	if (sep_nonce) {
		plist_dict_set_item(parameters, "ApSepNonce", plist_new_data((const char*)sep_nonce, sep_nonce_size));
		free(sep_nonce);
	}

	plist_dict_set_item(parameters, "ApProductionMode", plist_new_bool(1));
	if (client->image4supported) {
		plist_dict_set_item(parameters, "ApSecurityMode", plist_new_bool(1));
		plist_dict_set_item(parameters, "ApSupportsImg4", plist_new_bool(1));
	} else {
		plist_dict_set_item(parameters, "ApSupportsImg4", plist_new_bool(0));
	}

	tss_parameters_add_from_manifest(parameters, build_identity, true);

	// Add Ap,LocalPolicy
	uint8_t digest[SHA384_DIGEST_LENGTH];
	sha384(lpol_file, lpol_file_length, digest);
	plist_t lpol = plist_new_dict();
	plist_dict_set_item(lpol, "Digest", plist_new_data((char*)digest, SHA384_DIGEST_LENGTH));
	plist_dict_set_item(lpol, "Trusted", plist_new_bool(1));
	plist_dict_set_item(parameters, "Ap,LocalPolicy", lpol);

	// Add Ap,NextStageIM4MHash
	// Get previous TSS ticket
	uint8_t* ticket = NULL;
	uint32_t ticket_length = 0;
	tss_response_get_ap_img4_ticket(client->tss, &ticket, &ticket_length);
	// Hash it and add it as Ap,NextStageIM4MHash
	uint8_t hash[SHA384_DIGEST_LENGTH];
	sha384(ticket, ticket_length, hash);
	plist_dict_set_item(parameters, "Ap,NextStageIM4MHash", plist_new_data((char*)hash, SHA384_DIGEST_LENGTH));

	/* create basic request */
	request = tss_request_new(NULL);
	if (request == NULL) {
		logger(LL_ERROR, "Unable to create TSS request\n");
		plist_free(parameters);
		return -1;
	}

	/* add common tags from manifest */
	if (tss_request_add_local_policy_tags(request, parameters) < 0) {
		logger(LL_ERROR, "Unable to add common tags to TSS request\n");
		plist_free(request);
		plist_free(parameters);
		return -1;
	}

	/* send request and grab response */
	response = tss_request_send(request, client->tss_url);
	if (response == NULL) {
		logger(LL_INFO, "ERROR: Unable to send TSS request\n");
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

void fixup_tss(plist_t tss)
{
	plist_t node;
	plist_t node2;
	node = plist_dict_get_item(tss, "RestoreLogo");
	if (node && (plist_get_node_type(node) == PLIST_DICT) && (plist_dict_get_size(node) == 0)) {
		node2 = plist_dict_get_item(tss, "AppleLogo");
		if (node2 && (plist_get_node_type(node2) == PLIST_DICT)) {
			plist_dict_remove_item(tss, "RestoreLogo");
			plist_dict_set_item(tss, "RestoreLogo", plist_copy(node2));
		}
	}
	node = plist_dict_get_item(tss, "RestoreDeviceTree");
	if (node && (plist_get_node_type(node) == PLIST_DICT) && (plist_dict_get_size(node) == 0)) {
		node2 = plist_dict_get_item(tss, "DeviceTree");
		if (node2 && (plist_get_node_type(node2) == PLIST_DICT)) {
			plist_dict_remove_item(tss, "RestoreDeviceTree");
			plist_dict_set_item(tss, "RestoreDeviceTree", plist_copy(node2));
		}
	}
	node = plist_dict_get_item(tss, "RestoreKernelCache");
	if (node && (plist_get_node_type(node) == PLIST_DICT) && (plist_dict_get_size(node) == 0)) {
		node2 = plist_dict_get_item(tss, "KernelCache");
		if (node2 && (plist_get_node_type(node2) == PLIST_DICT)) {
			plist_dict_remove_item(tss, "RestoreKernelCache");
			plist_dict_set_item(tss, "RestoreKernelCache", plist_copy(node2));
		}
	}
}

int build_manifest_get_identity_count(plist_t build_manifest)
{
	// fetch build identities array from BuildManifest
	plist_t build_identities_array = plist_dict_get_item(build_manifest, "BuildIdentities");
	if (!build_identities_array || plist_get_node_type(build_identities_array) != PLIST_ARRAY) {
		logger(LL_ERROR, "Unable to find build identities node\n");
		return -1;
	}
	return plist_array_get_size(build_identities_array);
}

int extract_component(ipsw_archive_t ipsw, const char* path, void** component_data, size_t* component_size)
{
	char* component_name = NULL;
	if (!ipsw || !path || !component_data || !component_size) {
		return -1;
	}

	component_name = strrchr(path, '/');
	if (component_name != NULL)
		component_name++;
	else
		component_name = (char*) path;

	logger(LL_INFO, "Extracting %s (%s)...\n", component_name, path);
	if (ipsw_extract_to_memory(ipsw, path, component_data, component_size) < 0) {
		logger(LL_ERROR, "Unable to extract %s from %s\n", component_name, ipsw->path);
		return -1;
	}

	return 0;
}

int personalize_component(struct idevicerestore_client_t* client, const char *component_name, const void* component_data, size_t component_size, plist_t tss_response, void** personalized_component, size_t* personalized_component_size)
{
	void* component_blob = NULL;
	void* stitched_component = NULL;
	size_t stitched_component_size = 0;

	if (tss_response && plist_dict_get_item(tss_response, "ApImg4Ticket")) {
		/* stitch ApImg4Ticket into IMG4 file */
		img4_stitch_component(component_name, component_data, component_size, client->parameters, tss_response, &stitched_component, &stitched_component_size);
	} else {
		/* try to get blob for current component from tss response */
		if (tss_response && tss_response_get_blob_by_entry(tss_response, component_name, (unsigned char**)&component_blob) < 0) {
			logger(LL_DEBUG, "NOTE: No SHSH blob found for component %s\n", component_name);
		}

		if (component_blob != NULL) {
			if (img3_stitch_component(component_name, component_data, component_size, component_blob, 64, &stitched_component, &stitched_component_size) < 0) {
				logger(LL_ERROR, "Unable to replace %s IMG3 signature\n", component_name);
				free(component_blob);
				return -1;
			}
		} else {
			logger(LL_INFO, "Not personalizing component %s...\n", component_name);
			stitched_component = (unsigned char*)malloc(component_size);
			if (stitched_component) {
				stitched_component_size = component_size;
				memcpy(stitched_component, component_data, component_size);
			}
		}
	}
	free(component_blob);

	if (client->flags & FLAG_KEEP_PERS) {
		write_file(component_name, stitched_component, stitched_component_size);
	}

	*personalized_component = stitched_component;
	*personalized_component_size = stitched_component_size;
	return 0;
}

int build_manifest_check_compatibility(plist_t build_manifest, const char* product)
{
	int res = -1;
	plist_t node = plist_dict_get_item(build_manifest, "SupportedProductTypes");
	if (!node || (plist_get_node_type(node) != PLIST_ARRAY)) {
		logger(LL_DEBUG, "%s: ERROR: SupportedProductTypes key missing\n", __func__);
		logger(LL_DEBUG, "%s: WARNING: If attempting to install iPhoneOS 2.x, be advised that Restore.plist does not contain the\n", __func__);
		logger(LL_DEBUG, "%s: WARNING: key 'SupportedProductTypes'. Recommendation is to manually add it to the Restore.plist.\n", __func__);
		return -1;
	}
	uint32_t pc = plist_array_get_size(node);
	uint32_t i;
	for (i = 0; i < pc; i++) {
		plist_t prod = plist_array_get_item(node, i);
		if (plist_get_node_type(prod) == PLIST_STRING) {
			char *val = NULL;
			plist_get_string_val(prod, &val);
			if (val && (strcmp(val, product) == 0)) {
				res = 0;
				free(val);
				break;
			}
		}
	}
	return res;
}

void build_manifest_get_version_information(plist_t build_manifest, struct idevicerestore_client_t* client)
{
	plist_t node = NULL;
	client->version = NULL;
	client->build = NULL;

	node = plist_dict_get_item(build_manifest, "ProductVersion");
	if (!node || plist_get_node_type(node) != PLIST_STRING) {
		logger(LL_ERROR, "Unable to find ProductVersion node\n");
		return;
	}
	plist_get_string_val(node, &client->version);

	node = plist_dict_get_item(build_manifest, "ProductBuildVersion");
	if (!node || plist_get_node_type(node) != PLIST_STRING) {
		logger(LL_ERROR, "Unable to find ProductBuildVersion node\n");
		return;
	}
	plist_get_string_val(node, &client->build);

	client->build_major = strtoul(client->build, NULL, 10);
}

void build_identity_print_information(plist_t build_identity)
{
	char* value = NULL;
	plist_t info_node = NULL;
	plist_t node = NULL;

	info_node = plist_dict_get_item(build_identity, "Info");
	if (!info_node || plist_get_node_type(info_node) != PLIST_DICT) {
		logger(LL_ERROR, "Unable to find Info node\n");
		return;
	}

	node = plist_dict_get_item(info_node, "Variant");
	if (!node || plist_get_node_type(node) != PLIST_STRING) {
		logger(LL_ERROR, "Unable to find Variant node\n");
		return;
	}
	plist_get_string_val(node, &value);

	logger(LL_INFO, "Variant: %s\n", value);

	if (strstr(value, RESTORE_VARIANT_UPGRADE_INSTALL))
		logger(LL_INFO, "This restore will update the device without erasing user data.\n");
	else if (strstr(value, RESTORE_VARIANT_ERASE_INSTALL))
		logger(LL_INFO, "This restore will erase all device data.\n");
	else
		logger(LL_INFO, "Unknown Variant '%s'\n", value);

	free(value);

	info_node = NULL;
	node = NULL;
}

int build_identity_check_components_in_ipsw(plist_t build_identity, ipsw_archive_t ipsw)
{
	plist_t manifest_node = plist_dict_get_item(build_identity, "Manifest");
	if (!manifest_node || plist_get_node_type(manifest_node) != PLIST_DICT) {
		return -1;
	}
	int res = 0;
	plist_dict_iter iter = NULL;
	plist_dict_new_iter(manifest_node, &iter);
	plist_t node = NULL;
	char *key = NULL;
	do {
		node = NULL;
		key = NULL;
		plist_dict_next_item(manifest_node, iter, &key, &node);
		if (key && node) {
			plist_t path = plist_access_path(node, 2, "Info", "Path");
			if (path) {
				char *comp_path = NULL;
				plist_get_string_val(path, &comp_path);
				if (comp_path) {
					if (!ipsw_file_exists(ipsw, comp_path)) {
						logger(LL_ERROR, "%s file %s not found in IPSW\n", key, comp_path);
						res = -1;
					}
					free(comp_path);
				}
			}
		}
		free(key);
	} while (node);
	return res;
}

int build_identity_has_component(plist_t build_identity, const char* component)
{
	plist_t manifest_node = plist_dict_get_item(build_identity, "Manifest");
	if (!manifest_node || plist_get_node_type(manifest_node) != PLIST_DICT) {
		return 0;
	}

	plist_t component_node = plist_dict_get_item(manifest_node, component);
	if (!component_node || plist_get_node_type(component_node) != PLIST_DICT) {
		return 0;
	}

	return 1;
}

int build_identity_get_component_path(plist_t build_identity, const char* component, char** path)
{
	char* filename = NULL;

	plist_t manifest_node = plist_dict_get_item(build_identity, "Manifest");
	if (!manifest_node || plist_get_node_type(manifest_node) != PLIST_DICT) {
		logger(LL_ERROR, "Unable to find manifest node\n");
		if (filename)
			free(filename);
		return -1;
	}

	plist_t component_node = plist_dict_get_item(manifest_node, component);
	if (!component_node || plist_get_node_type(component_node) != PLIST_DICT) {
		logger(LL_ERROR, "Unable to find component node for %s\n", component);
		if (filename)
			free(filename);
		return -1;
	}

	plist_t component_info_node = plist_dict_get_item(component_node, "Info");
	if (!component_info_node || plist_get_node_type(component_info_node) != PLIST_DICT) {
		logger(LL_ERROR, "Unable to find component info node for %s\n", component);
		if (filename)
			free(filename);
		return -1;
	}

	plist_t component_info_path_node = plist_dict_get_item(component_info_node, "Path");
	if (!component_info_path_node || plist_get_node_type(component_info_path_node) != PLIST_STRING) {
		logger(LL_ERROR, "Unable to find component info path node for %s\n", component);
		if (filename)
			free(filename);
		return -1;
	}
	plist_get_string_val(component_info_path_node, &filename);

	*path = filename;
	return 0;
}

const char* get_component_name(const char* filename)
{
	struct filename_component_map {
		const char *fnprefix;
		int matchlen;
		const char *compname;
	};
	struct filename_component_map fn_comp_map[] = {
		{ "LLB", 3, "LLB" },
		{ "iBoot", 5, "iBoot" },
		{ "DeviceTree", 10, "DeviceTree" },
		{ "applelogo", 9, "AppleLogo" },
		{ "liquiddetect", 12, "Liquid" },
		{ "lowpowermode", 12, "LowPowerWallet0" },
		{ "recoverymode", 12, "RecoveryMode" },
		{ "batterylow0", 11, "BatteryLow0" },
		{ "batterylow1", 11, "BatteryLow1" },
		{ "glyphcharging", 13, "BatteryCharging" },
		{ "glyphplugin", 11, "BatteryPlugin" },
		{ "batterycharging0", 16, "BatteryCharging0" },
		{ "batterycharging1", 16, "BatteryCharging1" },
		{ "batteryfull", 11, "BatteryFull" },
		{ "needservice", 11, "NeedService" },
		{ "SCAB", 4, "SCAB" },
		{ "sep-firmware", 12, "RestoreSEP" },
		{ NULL, 0, NULL }
	};
	int i = 0;
	while (fn_comp_map[i].fnprefix) {
		if (!strncmp(filename, fn_comp_map[i].fnprefix, fn_comp_map[i].matchlen)) {
			return fn_comp_map[i].compname;
		}
		i++;
	}
	logger(LL_WARNING, "Unhandled component '%s'", filename);
	return NULL;
}
