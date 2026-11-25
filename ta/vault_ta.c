// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "include/vault_ta.h"
#include <trace.h>

TEE_Result TA_CreateEntryPoint(void)
{

	DMSG("EntryPoint Created");

	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	DMSG("Destroy EntryPoint");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t ptype, TEE_Param params[4], void __unused **session_id_ptr)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
											   TEE_PARAM_TYPE_NONE,
											   TEE_PARAM_TYPE_NONE,
											   TEE_PARAM_TYPE_NONE);

	if (exp_param_types != ptype)
		return TEE_ERROR_BAD_PARAMETERS;

	if (TEE_MemCompare(TA_VAULT_PASSWORD, params[0].memref.buffer, params[0].memref.size) != 0)
	{
		IMSG("Access refused");
		return TEE_ERROR_ACCESS_DENIED;
	}

	DMSG("Session openned");

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *sess_ptr)
{
}

void secure_free(void *buffer, size_t buffer_size) 
{
		TEE_MemFill(buffer, 0, buffer_size);
		TEE_Free(buffer);
}

TEE_Result delete_data(uint32_t params_types, TEE_Param params[4]) {
	TEE_ObjectHandle object = TEE_HANDLE_NULL;
	TEE_Result res;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
											   TEE_PARAM_TYPE_NONE,
											   TEE_PARAM_TYPE_NONE,
											   TEE_PARAM_TYPE_NONE);

	if (exp_param_types != params_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[0].memref.size > TEE_OBJECT_ID_MAX_LEN) {
		return TEE_ERROR_EXCESS_DATA;
	}

	if (params[0].memref.size == 0) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	size_t obj_id_size = params[0].memref.size;
	char *obj_id = TEE_Malloc(obj_id_size, 0);
	if (!obj_id) {
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_size);

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, obj_id, obj_id_size, TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META, &object);
	if (res != TEE_SUCCESS) {
		EMSG("Persistent object openning failed : %x", res);
		secure_free(obj_id, obj_id_size);
		return res;
	}

	res = TEE_CloseAndDeletePersistentObject1(object);
	if (res != TEE_SUCCESS) {
		EMSG("Persistent object deletion failed : %x", res);
	}

	secure_free(obj_id, obj_id_size);
	return res;
}


TEE_Result read_data(uint32_t params_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
											   TEE_PARAM_TYPE_MEMREF_OUTPUT,
											   TEE_PARAM_TYPE_NONE,
											   TEE_PARAM_TYPE_NONE);

	if (exp_param_types != params_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[0].memref.size > TEE_OBJECT_ID_MAX_LEN) {
		return TEE_ERROR_EXCESS_DATA;
	}

	if (params[0].memref.size == 0) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	size_t obj_id_size = params[0].memref.size;
	char *obj_id = TEE_Malloc(obj_id_size, 0);
	if (!obj_id) {
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_size);

	size_t obj_data_size = params[1].memref.size;
	char *obj_data = TEE_Malloc(obj_data_size, 0);
	if (!obj_data) {
		secure_free(obj_id, obj_id_size);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	TEE_MemMove(obj_data, params[1].memref.buffer, obj_data_size);

	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ;
	TEE_ObjectHandle object = TEE_HANDLE_NULL;
	TEE_Result res;
	TEE_ObjectInfo object_info = { };

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, obj_id, obj_id_size, flags, &object);
	if (res != TEE_SUCCESS) {
		EMSG("Persistent object openning failed : %x", res);
		params[1].memref.size = 0;
		secure_free(obj_data, obj_data_size);
		secure_free(obj_id, obj_id_size);
		return res;
	}

	res = TEE_GetObjectInfo1(object, &object_info);
	if (res != TEE_SUCCESS) {
		EMSG("Object data get info failed : %x", res);
		secure_free(obj_data, obj_data_size);
		secure_free(obj_id, obj_id_size);
		return res;
	}

	if (object_info.dataSize > obj_data_size) {
		secure_free(obj_data, obj_data_size);
		secure_free(obj_id, obj_id_size);
		params[1].memref.size = object_info.dataSize;

		return TEE_ERROR_SHORT_BUFFER;
	}

	uint32_t count = 0;
	res = TEE_ReadObjectData(object, obj_data, object_info.dataSize, &count);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_ReadObjectData failed 0x%08x, read %" PRIu32 " over %u",
				res, count, object_info.dataSize);
		return res;
	}

	TEE_MemMove(params[1].memref.buffer, obj_data, count);

	TEE_CloseObject(object);

	return res;

}

TEE_Result write_data(uint32_t params_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
											   TEE_PARAM_TYPE_MEMREF_INPUT,
											   TEE_PARAM_TYPE_NONE,
											   TEE_PARAM_TYPE_NONE);

	if (exp_param_types != params_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[0].memref.size > TEE_OBJECT_ID_MAX_LEN || params[1].memref.size > TA_MAX_SECRET_SIZE) {
		return TEE_ERROR_EXCESS_DATA;
	}

	if (params[0].memref.size == 0 || params[1].memref.size == 0) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	size_t obj_id_size = params[0].memref.size;
	char *obj_id = TEE_Malloc(obj_id_size, 0);
	if (!obj_id) {
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_size);

	size_t obj_data_size = params[1].memref.size;
	char *obj_data = TEE_Malloc(obj_data_size, 0);
	if (!obj_data) {
		TEE_Free(obj_id);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	TEE_MemMove(obj_data, params[1].memref.buffer, obj_data_size);

	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE;
	TEE_ObjectHandle object = NULL;

	TEE_Result res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, obj_id, obj_id_size, flags, TEE_HANDLE_NULL, obj_data, obj_data_size, &object);
	if (res != TEE_SUCCESS) {
		secure_free(obj_data, obj_data_size);

		EMSG("Persistent object creation failed : %x", res);
		return res;
	}

	TEE_CloseObject(object);

	secure_free(obj_data, obj_data_size);
	return res;
}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *session_id,
                                      uint32_t command_id,
                                      uint32_t params_type,
                                      TEE_Param parameters[4])
{
    switch (command_id)
    {
    case TA_VAULT_CMD_WRITE_DATA:
        return write_data(params_type, parameters);
    case TA_VAULT_CMD_READ_DATA:
        return read_data(params_type, parameters);
    case TA_VAULT_CMD_DELETE_DATA:
        return delete_data(params_type, parameters);
    default:
        return TEE_ERROR_NOT_SUPPORTED;
    }
}