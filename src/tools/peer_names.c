// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Luis Ressel <aranea@aixah.de>. All Rights Reserved.
 */

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "containers.h"
#include "encoding.h"
#include "peer_names.h"

static bool parse_peer_name(char *line, struct wgpeer_name *slot)
{
	size_t len = strlen(line);

	// TODO: Use strtok() for this and the next paragraph?
	//       More readable, more flexible, ever so slightly slower
	if ((len < WG_KEY_LEN_BASE64) || line[WG_KEY_LEN_BASE64 - 1] != ' ')
		return false;
	line[WG_KEY_LEN_BASE64 - 1] = '\0';
	if (!key_from_base64(slot->public_key, line))
		return false;

	if (line[len - 1] == '\n')
		line[len - 1] = '\0';

	slot->name = strdup(line + WG_KEY_LEN_BASE64);
	if (!slot->name)
		return false;
	return true;
}

static int peer_name_cmp(const void *a, const void *b)
{
	const struct wgpeer_name *x = a, *y = b;
	return memcmp(x->public_key, y->public_key, WG_KEY_LEN);
}

struct wgpeer_names *peer_names_open(struct wgdevice *device)
{
	size_t max_peers = 1, peers = 0, buf_len = 0, path_len;
	struct wgpeer_name *arr, *arr2;
	struct wgpeer_names *names;
	char *buf = NULL, *path;
	FILE *f;

	path = getenv("WG_PEER_NAMES");
	if (!path || !path[0])
		return NULL;

	path_len = strlen(path);
	if (path[path_len - 1] == '/') {
		char path2[path_len + strlen(device->name) + 1];
		strcpy(path2, path);
		strcpy(path2 + path_len, device->name);
		f = fopen(path2, "r");
	} else
		f = fopen(path, "r");
	if (!f)
		return NULL; // TODO: warning?

	names = malloc(sizeof(struct wgpeer_names));
	if (!names)
		return NULL; // TODO: warning?
	arr = malloc(sizeof(struct wgpeer_name));
	if (!names->arr) {
		free(names);
		return NULL; // TODO: warning?
	}

	while (getline(&buf, &buf_len, f) >= 0) {
		if (parse_peer_name(buf, &arr[peers]) && (++peers == max_peers)) {
			// TODO: Pulled this overflow check out of my ass, gotta revisit it later
			if (SIZE_MAX / (2 * sizeof(struct wgpeer_name)) < max_peers)
				return NULL; // TODO: warning?
			max_peers *= 2;

			arr2 = realloc(arr, max_peers * sizeof(struct wgpeer_name));
			if (!arr2) {
				free(arr);
				return NULL; // TODO: warning?
			}
			arr = arr2;
		}
	}

	free(buf);
	if (!peers) {
		free(names);
		free(arr);
	}
	if ((arr2 = realloc(arr, peers * sizeof(struct wgpeer_name))))
			arr = arr2;

	qsort(arr, peers, sizeof(struct wgpeer_name), peer_name_cmp);
	names->len = peers;
	names->arr = arr;
	return names;
}

void peer_names_free(struct wgpeer_names *names)
{
	if (!names)
		return;

	for (size_t i = 0; i < names->len; ++i)
		free(names->arr[i].name);
	free(names->arr);
	free(names);
}

char *peer_names_get(struct wgpeer_names *names, uint8_t key[static WG_KEY_LEN])
{
	size_t r, l = 0;

	if (!names || !names->len)
		return NULL;
	r = names->len - 1;

	while (l <= r) {
		size_t m = l + (r - l) / 2;
		int cmp = memcmp(key, names->arr[m].public_key, WG_KEY_LEN);
		if (!cmp)
			return names->arr[m].name;
		else if (cmp > 0)
			l = m + 1;
		else if (!m)
			break;
		else
			r = m - 1;
	}
	return NULL;
}
