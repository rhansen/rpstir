/* ***** BEGIN LICENSE BLOCK *****
 *
 * BBN Address and AS Number PKI Database/repository software
 * Version 1.0
 *
 * US government users are permitted unrestricted rights as
 * defined in the FAR.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) BBN Technologies 2007.  All Rights Reserved.
 *
 * Contributor(s):  David Montana
 *
 * ***** END LICENSE BLOCK ***** */

/*
  $Id: query.c 857 2009-09-30 15:27:40Z dmontana $
*/

/************************
 * Server that implements RTR protocol
 ***********************/

#include "pdu.h"
#include "socket.h"
#include "err.h"
#include "rtrUtils.h"
#include "querySupport.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static scm      *scmp = NULL;
static scmcon   *connect = NULL;
static scmsrcha *fullSrch = NULL;
static scmtab   *fullTable = NULL;

static int sock;
static PDU response;
static IPPrefixData prefixData;

/* callback that sends a single address to the client */
static int sendResponse(scmcon *conp, scmsrcha *s, int numLine) {
	char *ptr1 = (char *)s->vec[1].valptr, *ptr2;
	conp = conp; numLine = numLine;

	response.typeSpecificData = &prefixData;
	prefixData.flags = FLAG_ANNOUNCE;
	prefixData.dataSource = SOURCE_RPKI;
	prefixData.asNumber = *((uint *)s->vec[0].valptr);

	ptr2 = strchr(ptr1, '/');
	*ptr2 = '\0';
	// IPv4
	if (strchr(ptr1, '.')) {
	  fillInPDUHeader(&response, PDU_IPV4_PREFIX, 0);
	  uint val = 0;
	  ptr1 = strtok(ptr1, ".");
	  while (ptr1) {
		val = (val << 8) + atoi(ptr1);
		ptr1 = strtok(NULL, ".");
	  }
	  prefixData.ipAddress[0] = val;
	}
	// IPv6
	else {
	  fillInPDUHeader(&response, PDU_IPV6_PREFIX, 0);
	  uint i = 0, val = 0, final = 0;
	  ptr1 = strtok(ptr1, ":");
	  while (ptr1) {
		val = (val << 16) + atoi(ptr1);
		if (final) {
		  prefixData.ipAddress[i] = val;
		  val = 0;
		  i++;
		}
		final = ! final;
		ptr1 = strtok(NULL, ":");
	  }
	}

	ptr1 = ptr2 + 1;
	ptr2 = strchr(ptr1, '/');
	if (ptr2) *ptr2 = '\0';
	prefixData.prefixLength = atoi(ptr1);
	prefixData.maxLength = ptr2 ? atoi(ptr2+1) : prefixData.prefixLength;
	if (writePDU(&response, sock) == -1) {
	  printf("Error writing response\n");
	  return -1;
	}

	return 0;
}

static void handleSerialQuery(PDU *request) {
}

static void handleResetQuery() {
	uint serialNum;

	fillInPDUHeader(&response, PDU_CACHE_RESPONSE, 1);
	if (writePDU(&response, sock) == -1) {
		printf("Error writing cache response\n");
		return;
	}
	serialNum = getLastSerialNumber(connect, scmp);

	// setup up the query if this is the first time
	if (fullSrch == NULL) {
		fullSrch = newsrchscm(NULL, 2, 0, 1);
		addcolsrchscm(fullSrch, "asn", SQL_C_ULONG, 8);
		addcolsrchscm(fullSrch, "ip_addr", SQL_C_CHAR, 50);
		snprintf (fullSrch->wherestr, WHERESTR_SIZE,
				  "serial_num = %d", serialNum);
		fullTable = findtablescm(scmp, "rtr_full");
	}

	// do the query, with callback sending out the responses
	searchscm (connect, fullTable, fullSrch, NULL,
			   sendResponse, SCM_SRCH_DOVALUE_ALWAYS, NULL);

	// finish up by sending the end of data PDU
	fillInPDUHeader(&response, PDU_END_OF_DATA, 0);
	response.typeSpecificData = &serialNum;
	if (writePDU(&response, sock) == -1) {
		printf("Error writing end of data\n");
		return;
	}
}

int main(int argc, char **argv) {
	PDU *request;
	char msg[1024];

	// start listening on server socket
	if ((sock = getServerSocket()) == -1) {
		printf("Error opening socket\n");
		return -1;
	}

	// initialize the database connection
	scmp = initscm();
	checkErr(scmp == NULL, "Cannot initialize database schema\n");
	connect = connectscm (scmp->dsn, msg, sizeof(msg));
	checkErr(connect == NULL, "Cannot connect to database: %s\n", msg);

	while ((request = readPDU(sock))) {
		switch (request->pduType) {
		case PDU_SERIAL_QUERY:
			handleSerialQuery(request);
			break;
		case PDU_RESET_QUERY:
			handleResetQuery();
			break;
		default:
			printf("Cannot handle request of type %d\n", request->pduType);
		}
	}
	return 1;
}
