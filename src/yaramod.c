/***

Copyright (C) 2015, 2016 Teclib'

This file is part of Armadito module YARA.

Armadito module YARA is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Armadito module YARA is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Armadito module YARA.  If not, see <http://www.gnu.org/licenses/>.

***/

#include <libarmadito.h>
#include <yara.h>

struct yara_data {
	YR_COMPILER *compiler;
};

static enum a6o_mod_status yara_init(struct a6o_module *module)
{
	struct yara_data *yr_data;
	int ret;

	if ((ret = yr_initialize()) != ERROR_SUCCESS) {
		a6o_log(ARMADITO_LOG_MODULE, ARMADITO_LOG_LEVEL_ERROR, "YARA initialization failed: %d", ret);
		return ARMADITO_MOD_INIT_ERROR;
	}

	yr_data->compiler = NULL;

	if ((ret = yr_compiler_create(&yr_data->compiler)) != ERROR_SUCCESS) {
		a6o_log(ARMADITO_LOG_MODULE, ARMADITO_LOG_LEVEL_ERROR, "YARA compiler creation failed: %s", ret);
		return ARMADITO_MOD_INIT_ERROR;
	}

	yr_data = malloc(sizeof(struct yara_data));
	module->data = yr_data;

	return ARMADITO_MOD_OK;
}

static enum a6o_mod_status yara_conf_set_dbdir(struct a6o_module *module, const char *key, struct a6o_conf_value *value)
{
	struct yara_data *yr_data = (struct yara_data *)module->data;

	return ARMADITO_MOD_OK;
}

static enum a6o_mod_status yara_post_init(struct a6o_module *module)
{
	struct yara_data *yr_data = (struct yara_data *)module->data;

	return ARMADITO_MOD_OK;
}

static enum a6o_file_status yara_scan(struct a6o_module *module, int fd, const char *path, const char *mime_type, char **pmod_report)
{
	struct yara_data *yr_data = (struct yara_data *)module->data;

	return ARMADITO_CLEAN;
}

static enum a6o_mod_status yara_close(struct a6o_module *module)
{
	struct yara_data *yr_data = (struct yara_data *)module->data;

	return ARMADITO_MOD_OK;
}

static enum a6o_update_status yara_info(struct a6o_module *module, struct a6o_module_info *info)
{
	return ARMADITO_UPDATE_NON_AVAILABLE;
}

static struct a6o_conf_entry yara_conf_table[] = {
	{ "dbdir", CONF_TYPE_STRING, yara_conf_set_dbdir},
	{ NULL, CONF_TYPE_VOID, NULL},
};

static const char *yara_mime_types[] = { "*", NULL, };

struct a6o_module module = {
	.init_fun = yara_init,
	.conf_table = yara_conf_table,
	.post_init_fun = yara_post_init,
	.scan_fun = yara_scan,
	.close_fun = yara_close,
	.info_fun = yara_info,
	.supported_mime_types = yara_mime_types,
	.name = "yara",
	.size = sizeof(struct yara_data),
};

