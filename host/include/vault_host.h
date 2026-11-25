/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016-2017, Linaro Limited
 * All rights reserved.
 */
#ifndef TA_VAULT_H
#define TA_VAULT_H


/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_VAULT_UUID \
	{ 0xa8c1e85b, 0x67a9, 0x4d9d, \
		{ 0x9e, 0x40, 0x01, 0x35, 0xb6, 0xc3, 0xa3, 0xe3} }

/* The function IDs implemented in this TA */
#define TA_VAULT_CMD_WRITE_DATA		0
#define TA_VAULT_CMD_READ_DATA		1
#define TA_VAULT_CMD_DELETE_DATA	2

#define READ_SIZE	7000

#endif /*TA_VAULT_H*/
