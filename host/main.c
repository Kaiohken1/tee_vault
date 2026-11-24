// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include "include/vault_host.h"

typedef struct
{
	char *buffer;
	size_t buffer_length;
	ssize_t input_length;
} InputBuffer;

InputBuffer *new(void)
{
	InputBuffer *input_buffer = (InputBuffer *)malloc(sizeof(InputBuffer));
	input_buffer->buffer = NULL;
	input_buffer->buffer_length = 0;
	input_buffer->input_length = 0;

	return input_buffer;
}

void read_input(InputBuffer *input_buffer)
{
	ssize_t bytes_read = getline(&(input_buffer->buffer), &(input_buffer->buffer_length), stdin);

	if (bytes_read <= 0)
	{
		printf("Error reading input\n");
		exit(EXIT_FAILURE);
	}

	input_buffer->input_length = bytes_read - 1;
	input_buffer->buffer[bytes_read - 1] = 0;
}

void client_read_data(TEEC_Session sess, TEEC_Operation op) {
	InputBuffer *obj_id = new();
	// InputBuffer *obj_read_data = new();
	//TODO Change read buffer
	char read_data[7000];
	uint32_t err_origin;
	TEEC_Result res;

	printf("vault > Write entry name to search : ");
	read_input(obj_id);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
									 TEEC_NONE, TEEC_NONE);
	
	op.params[0].tmpref.buffer = obj_id->buffer;
	op.params[0].tmpref.size = obj_id->input_length;

	op.params[1].tmpref.buffer = read_data;
	op.params[1].tmpref.size = sizeof(read_data);

	res = TEEC_InvokeCommand(&sess, TA_VAULT_CMD_READ_DATA, &op,
					&err_origin);
	
	if (res != TEEC_SUCCESS)
		errx(1, "vault > Failed to read data : code 0x%x origin 0x%u",
			res, err_origin);
	
	printf("vault > data read : %s\n", op.params[1].tmpref.buffer);
}

void client_write_data(TEEC_Session sess, TEEC_Operation op) {
	InputBuffer *obj_id = new();
	InputBuffer *obj_data = new();
	uint32_t err_origin;

	printf("vault > Write entry name : ");
	read_input(obj_id);

	printf("vault > Write data to save : ");
	read_input(obj_data);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
									 TEEC_NONE, TEEC_NONE);
	
	op.params[0].tmpref.buffer = obj_id->buffer;
	op.params[0].tmpref.size = obj_id->input_length;

	op.params[1].tmpref.buffer = obj_data->buffer;
	op.params[1].tmpref.size = obj_data->input_length;

	TEEC_Result res = TEEC_InvokeCommand(&sess, TA_VAULT_CMD_WRITE_DATA, &op,
					&err_origin);
	
	if (res != TEEC_SUCCESS)
		errx(1, "vault > Failed to write data : code 0x%x origin 0x%u",
			res, err_origin);
	printf("vault > Data written successfully\n");
}

void repl(InputBuffer *input_buffer, TEEC_Session sess, TEEC_Operation op)
{
	while (true)
	{
		printf("vault > ");
		read_input(input_buffer);
		if (strncmp(input_buffer->buffer, "exit", 4) == 0)
		{
			printf("vault > [+] closing...\n");
			exit(EXIT_SUCCESS);
		}
		else if (strncmp(input_buffer->buffer, "write", 5) == 0)
		{
			client_write_data(sess, op);
		} 
		else if (strncmp(input_buffer->buffer, "read", 4) == 0)
		{
			client_read_data(sess, op);
		} 
		else
		{
			printf("vault > [!] unrecognized command\n");
		}
	}
}

int main(void)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_VAULT_UUID;
	uint32_t err_origin;

	res = TEEC_InitializeContext(NULL, &ctx);

	if (res != TEEC_SUCCESS)
		printf("Erreur lors de l'initialization du contexte %d", res);

	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
									 TEEC_NONE, TEEC_NONE);

	InputBuffer *input_buffer = new();
	printf("> Vault password : ");
	read_input(input_buffer);

	op.params[0].tmpref.buffer = input_buffer->buffer;
	op.params[0].tmpref.size = input_buffer->input_length;

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, &op, &err_origin);
	if (res != TEEC_SUCCESS)
	{
		errx(1, "Erreur lors de l'initialization de la session : code 0x%x origine 0x%u", res, err_origin);
		exit(EXIT_FAILURE);
	}

	repl(input_buffer, sess, op);

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	exit(EXIT_SUCCESS);
}
