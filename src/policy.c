#include "policy.h"
#include "error.h"

struct ncot_policy*
ncot_policy_new()
{
	struct ncot_policy *policy;
	policy = calloc(1, sizeof(struct ncot_policy));
	return policy;
}


void
ncot_policy_init(struct ncot_policy *policy)
{
	strncpy(policy->category, "Default category", strlen("Default category") + 1);
}

void
ncot_policy_free(struct ncot_policy **ppolicy)
{
	struct ncot_policy *policy;
	if (ppolicy) {
		policy = *ppolicy;
		if (policy) {
			free(policy);
			*ppolicy = NULL;
		} else
			NCOT_LOG_ERROR("Invalid ncot_policy\n");
	} else
		NCOT_LOG_ERROR("Invalid argument (*policy)\n");
}

struct ncot_policy*
ncot_policy_copy_deep(struct ncot_policy *policy)
{
	struct ncot_policy *newpolicy;
	if (!policy) {
		NCOT_LOG_ERROR("ncot_policy_copy_deep: Invalid policy parameter\n");
		return NULL;
	}
	newpolicy = ncot_policy_new();
	if (!policy) {
		NCOT_LOG_ERROR("ncot_policy_copy_deep: Out of mem\n");
		return NULL;
	}
	ncot_policy_set_brief(newpolicy, policy->brief);
	ncot_policy_set_category(newpolicy, policy->category);
	ncot_policy_set_text(newpolicy, (char*)policy->text);
	return newpolicy;
}

/** Set brief to a policy */
void
ncot_policy_set_brief(struct ncot_policy *policy, char *brief)
{
	if (!brief) return;
	if (!policy) {
		NCOT_LOG_ERROR("ncot_policy_set_brief: Invalid policy parameter\n");
		return;
	}
	strncpy(policy->brief, brief, NCOT_POLICY_BRIEF_LENGTH - 1);
        /*Make it double sure as we never overwrite the last byte and
	 * calloc our struct. */
	policy->brief[NCOT_POLICY_BRIEF_LENGTH - 1] = '\0';
}

/** Set category to a policy */
void
ncot_policy_set_category(struct ncot_policy *policy, char *category)
{
	if (!category) return;
	if (!policy) {
		NCOT_LOG_ERROR("ncot_policy_set_category: Invalid policy parameter\n");
		return;
	}
	strncpy(policy->category, category, NCOT_POLICY_CATEGORY_LENGTH - 1);
        /*Make it double sure as we never overwrite the last byte and
	 * calloc our struct. */
	policy->category[NCOT_POLICY_CATEGORY_LENGTH - 1] = '\0';
}

/** Add text to a policy */
void
ncot_policy_set_text(struct ncot_policy *policy, char *text)
{
	if (!text) return;
	if (!policy) {
		NCOT_LOG_ERROR("ncot_policy_set_text: Invalid policy parameter\n");
		return;
	}
	if (policy->text) free(policy->text);
	policy->text = NULL;
	policy->text = calloc(1, NCOT_POLICY_MAX_TEXT_LENGTH + 1);
	strncpy((char*)policy->text, (char*)text, NCOT_POLICY_MAX_TEXT_LENGTH);
	*policy->text[NCOT_POLICY_MAX_TEXT_LENGTH] = '\0';
	return;
}

/** Add a policy as a json object to the json array passed in in the
 * parent parameter */
void
ncot_policy_save_to_json(struct ncot_policy *policy, struct json_object *parent)
{
	int ret;
	char *string =  NULL;
	struct json_object *json;
	struct json_object *jsonobj;
	struct json_object *jsonarray;
	policy->json = json_object_new_object();
	jsonobj = json_object_new_string(policy->brief);
	json_object_object_add_ex(policy->json, "brief", jsonobj, JSON_C_OBJECT_KEY_IS_CONSTANT);
	jsonobj = json_object_new_string(policy->category);
	json_object_object_add_ex(policy->json, "category", jsonobj, JSON_C_OBJECT_KEY_IS_CONSTANT);
	jsonobj = json_object_new_string((char*)policy->text);
	json_object_object_add_ex(policy->json, "text", jsonobj, JSON_C_OBJECT_KEY_IS_CONSTANT);
	json_object_array_add(parent, policy->json);
	NCOT_LOG_VERBOSE("ncot_policy_save_to_json: policy saved\n");
}

/* Load policies from json object, store in an uthash and return it. */
struct ncot_policy*
ncot_policies_new_from_json(struct json_object *jsonobj)
{
	struct ncot_policy *policy;
	struct ncot_policy *policyresult;
	struct ncot_policy *policylist = NULL;
	struct json_object *jsonpolicy;
	struct json_object *jsonbrief;
	struct json_object *jsoncategory;
	struct json_object *jsontext;
	const char *string;
	int ret;
	int numpolicies;
	int i;
	int slen;
	numpolicies = json_object_array_length(jsonobj);
	for (i=0; i<numpolicies; i++) {
		jsonpolicy = json_object_array_get_idx(jsonobj, i);
		ret = json_object_object_get_ex(jsonpolicy, "brief", &jsonbrief);
		if (! ret) {
			NCOT_LOG_WARNING("ncot_policies_new_from_json: no field name \"brief\" in json, skipping policy\n");
			continue;
		}
		policy = ncot_policy_new();
		if (!policy) return policy;
		string = json_object_get_string(jsonbrief);
		strncpy(policy->brief, string, NCOT_POLICY_BRIEF_LENGTH);

		ret = json_object_object_get_ex(jsonpolicy, "category", &jsoncategory);
		if (! ret) {
			NCOT_LOG_WARNING("ncot_policies_new_from_json: no field name \"category\" in json, skipping policy\n");
			ncot_policy_free(&policy);
			continue;
		}
		string = json_object_get_string(jsoncategory);
		strncpy(policy->category, string, NCOT_POLICY_CATEGORY_LENGTH);

		ret = json_object_object_get_ex(jsonpolicy, "text", &jsontext);
		if (! ret) {
			NCOT_LOG_WARNING("ncot_policies_new_from_json: no field name \"text\" in json, skipping policy\n");
			ncot_policy_free(&policy);
			continue;
		}
		string = json_object_get_string(jsontext);
		slen = json_object_get_string_len(jsontext);
		if (slen > NCOT_POLICY_MAX_TEXT_LENGTH) slen = NCOT_POLICY_MAX_TEXT_LENGTH;
		policy->text = malloc(slen + 1);
		strncpy((char*)policy->text, string, slen);
		*policy->text[slen] = '\0';

		policyresult = NULL;
		HASH_FIND_STR(policylist, (char*)policy->text, policyresult);
		if (policyresult) {
			NCOT_LOG_WARNING("ncot_policies_new_from_json: policy with such key (text) already in hashtable, skipping\n");
			ncot_policy_free(&policy);
			continue;
		}
		HASH_ADD_PTR(policylist, text, policy);
		policy = NULL;
	}
	return policylist;
}
