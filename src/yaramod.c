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

/*
  (FD 2016/08/11) for now, we handle only one compiled rules file and do not compile the rules inside the module.
  Later, we may add rule compiling in module post_init and saving the compiled file, but there are some issues:
  * is compilation incremental? it seems that yes
  * can we mix compiled and non compiled rules?
 */

struct yara_data {
	const char *rule_file;
	YR_RULES *rules;
};

static enum a6o_mod_status yara_init(struct a6o_module *module)
{
	struct yara_data *yr_data;
	int ret;

	if ((ret = yr_initialize()) != ERROR_SUCCESS) {
		a6o_log(ARMADITO_LOG_MODULE, ARMADITO_LOG_LEVEL_WARNING, "YARA initialization failed: %d", ret);
		return ARMADITO_MOD_INIT_ERROR;
	}

	yr_data = malloc(sizeof(struct yara_data));
	module->data = yr_data;

	yr_data->rule_file = NULL;
	yr_data->rules = NULL;

	return ARMADITO_MOD_OK;
}

static enum a6o_mod_status yara_conf_set_rule_file(struct a6o_module *module, const char *key, struct a6o_conf_value *value)
{
	struct yara_data *yr_data = (struct yara_data *)module->data;

	yr_data->rule_file = strdup(a6o_conf_value_get_string(value));

	return ARMADITO_MOD_OK;
}

static size_t yara_count_rules(YR_RULES *rules)
{
	YR_RULE *rule;
	size_t count = 0;

	/* rules is a YR_RULES object */
	yr_rules_foreach(rules, rule)
	{
		count++;
	}

	return count;
}

static enum a6o_mod_status yara_post_init(struct a6o_module *module)
{
	struct yara_data *yr_data = (struct yara_data *)module->data;
	int ret;

	if ((ret = yr_rules_load(yr_data->rule_file, &yr_data->rules)) != ERROR_SUCCESS) {
		a6o_log(ARMADITO_LOG_MODULE, ARMADITO_LOG_LEVEL_WARNING, "YARA rules load failed: %d", ret);
		return ARMADITO_MOD_INIT_ERROR;
	}

	a6o_log(ARMADITO_LOG_MODULE, ARMADITO_LOG_LEVEL_INFO, "YARA rules loaded from %s, %d rules",
		yr_data->rule_file, yara_count_rules(yr_data->rules));

	return ARMADITO_MOD_OK;
}

struct yara_scan_data {
	enum a6o_file_status status;
	char *report;
};

static int yara_scan_callback(int message, void *message_data, void* user_data)
{
	struct yara_scan_data *scan_data = (struct yara_scan_data *)user_data;
	YR_RULE *rule = (YR_RULE *)message_data;

	switch(message) {
	case CALLBACK_MSG_RULE_MATCHING:
		scan_data->status = ARMADITO_MALWARE;
		scan_data->report = strdup(rule->identifier);
		return CALLBACK_CONTINUE;
	case CALLBACK_MSG_RULE_NOT_MATCHING:
		return CALLBACK_CONTINUE;
	}

	return CALLBACK_ERROR;
}

static enum a6o_file_status yara_scan(struct a6o_module *module, int fd, const char *path, const char *mime_type, char **pmod_report)
{
	struct yara_data *yr_data = (struct yara_data *)module->data;
	struct yara_scan_data scan_data;
	int ret;
	int flags = 0;

	flags |= SCAN_FLAGS_FAST_MODE;

	scan_data.status = ARMADITO_CLEAN;
	scan_data.report = NULL;

// File descriptor scan support in Yara is correct for us since 3.5.0
#if YR_MAJOR_VERSION > 3 || (YR_MAJOR_VERSION == 3 && YR_MINOR_VERSION >= 5)
	ret = yr_rules_scan_fd(yr_data->rules, (YR_FILE_DESCRIPTOR)fd, 0, yara_scan_callback, &scan_data, 1000000);
#else
	ret = yr_rules_scan_file(yr_data->rules, path, flags, yara_scan_callback, &scan_data, 1000000);
#endif

	if (scan_data.report != NULL)
		*pmod_report = scan_data.report;

	return scan_data.status;
}

static enum a6o_mod_status yara_close(struct a6o_module *module)
{
	struct yara_data *yr_data = (struct yara_data *)module->data;

	if (yr_data->rules != NULL)
		yr_rules_destroy(yr_data->rules);

	return ARMADITO_MOD_OK;
}

static enum a6o_update_status yara_info(struct a6o_module *module, struct a6o_module_info *info)
{
	return ARMADITO_UPDATE_NON_AVAILABLE;
}

static struct a6o_conf_entry yara_conf_table[] = {
	{ "rule_file", CONF_TYPE_STRING, yara_conf_set_rule_file},
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

