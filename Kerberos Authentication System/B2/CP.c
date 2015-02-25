/* client.c */
#include        <stdio.h>
#include        <rpc/rpc.h>
#include        "C1K.h"
#include        "C2S.h"
#include	<stdlib.h>
#include <string.h>
#include <md5.h>
#include "global.h"
#include "rsaref.h"
#include "Ckey.h"

main(argc, argv)
	int argc;char *argv[]; {
	CLIENT *cl; /* RPC handle */
	char *server;
	struct netReply* reply;
	struct encryptedkeyreply *encryptedreply;
	struct Request request;
	server = argv[3];

	unsigned char iv[8];
	memset(iv, '\0', 8);
	/********************************************/
	/* Set up connection with the server which provides services given in AS_PROG.
	 Connection is called client "handle." */
	if ((cl = clnt_create(server, CK_PROG, CK_VERS, "udp")) == NULL) {
		clnt_pcreateerror(server);
		exit(2);
	}

	char clientid[10];
	char serverid[10];
	/********************************************/
	//prepare argument for a service request
	request.requestLen = sizeof(struct Request);
	memset(request.C, '\0', 8);
	memset(request.S, '\0', 8);
	strncpy(clientid, argv[1], 8);
	strncpy(serverid, argv[2], 8);
	memcpy(request.C, clientid, 8);
	memcpy(request.S, serverid, 8);

	printf("Server 1 Request Phase\n ");
	printf("________________________\n");
	// call service passing the request
	if ((encryptedreply = requestsessionkey_1(request, cl)) == NULL) {
		clnt_perror(cl, "call failed");
		exit(3);
	}
	if (encryptedreply->encry_length != -1) {
		printf("Encrypted Reply:\n");
		int i;
		for (i = 0; i < encryptedreply->encry_length; i++) {
			printf("%03d ", (int) encryptedreply->ency_msg[i]);

		}
		printf("\n");
		char decryptedlocal[68];
		int decryptedlength;
		printf("Key used from decryption: %s\n", key);
		R_DecryptPEMBlock(decryptedlocal, &decryptedlength,
				encryptedreply->ency_msg, encryptedreply->encry_length, key,
				iv);
		decryptedlocal[68] = '\0';
		char junkkey[9];
		char junkkeytok[44];
		char junkserverid[9];
		char junkclientid[9];
		memcpy(junkclientid, decryptedlocal, 8);
		memcpy(junkserverid, decryptedlocal + 8, 8);
		memcpy(junkkey, decryptedlocal + 16, 8);
		memcpy(junkkeytok, decryptedlocal + 24, 44);
		junkkey[8] = '\0';
		junkclientid[8] = '\0';
		junkserverid[8] = '\0';
		junkkeytok[44] = '\0';
		printf("Received Reply from server 1\n");
		printf("Client : %s\n", junkclientid);
		printf("Server: %s\n", junkserverid);

		if (strncmp(junkclientid, clientid, 8) != 0
				|| strncmp(junkserverid, serverid, 8) != 0) {
			printf(
					"Bogus response Careful!! Response is not from the proper server !!\n");
			exit(2);
		}
		printf("Session Key:");

		for (i = 0; i < 8; i++)
			printf("%03d ", (int) junkkey[i]);
		printf("\n");
		printf("Encrypted token for the server:\n ");
		for (i = 0; i < 44; i++)
			printf("%03d ", (int) junkkeytok[i]);
		printf("\n");

		printf("Server 2 Request Phase\n");
		printf("________________________\n");

		CLIENT *cl1; /* RPC handle */
		char *server1;
		struct request req;
		struct encryptedmsg encrreq;
		struct response *result;
		struct encryptedreply *encreply;
		server1 = argv[4];
		int choice;
		/********************************************/
		/* Set up connection with the server which provides services given in AS_PROG.
		 Connection is called client "handle." */
		if ((cl1 = clnt_create(server1, CS_PROG, CS_VERS, "udp")) == NULL) {
			clnt_pcreateerror(server1);
			exit(2);
		}
		printf("Choose from the below options to run the services\n");
		printf(
				"1.Apha - removes all non-alphabetic character from the entered string\n");
		printf(
				"2.Numeric - removes all non-numeric characters from the entered string\n ");
		printf("Enter the option\n");
		scanf("%d", &choice);
		char idclient[10];
		char idserver[10];
		memset(req.C, '\0', 8);
		memset(req.S, '\0', 8);
		strcpy(idclient, argv[1]);
		strcpy(idserver, argv[2]);
		memcpy(req.C, idclient, 8);
		memcpy(req.S, idserver, 8);
		req.S[8] = '\0';
		req.C[8] = '\0';
		req.reqlen = sizeof(request);
		memcpy(req.token, junkkeytok, 44);
		char encryptedmsg[96];
		int encryptedmsglength;
		char arguments[68];
		char finalmsg[156];
		encrreq.encryptedrequestlength = 156;
		memset(encrreq.encryptedrequest, '\0', 156);
		switch (choice) {
		case 1:
			printf("Enter the value :\n");
			scanf("%s", req.a.s);

			printf("Key used to encrypt Message :\n");

			for (i = 0; i < 8; i++) {
				printf("%03d ", (int) junkkey[i]);
			}
			memset(arguments, '\0', 96);
			memcpy(arguments, req.a.s, 68);
			memset(encryptedmsg, '\0', 96);
			memset(finalmsg, '\0', 156);
			printf("Arguments : %s\n", arguments);
			printf("Token at client: %s\n", junkkeytok);
			printf("Encrypted Token at Client:");
			for (i = 0; i < strlen(junkkeytok); i++)
				printf("%03d ", (int) junkkeytok[i]);
			printf("\n");

			R_EncryptPEMBlock(encryptedmsg, &encryptedmsglength, arguments, 68,
					junkkey, iv);

			memcpy(finalmsg, idclient, 8);
			memcpy(finalmsg + 8, idserver, 8);
			memcpy(finalmsg + 16, encryptedmsg, 96);

			memcpy(finalmsg + 112, junkkeytok, 44);
		//	memcpy(finalmsg + 112, "Dummytoken", 44);
			finalmsg[156] = '\0';

			memcpy(encrreq.encryptedrequest, finalmsg, 156);
			encrreq.encryptedrequest[156] = '\0';
			printf("Encrypted Message Request : ");

			for (i = 0; i < encrreq.encryptedrequestlength; i++)
				printf("%03d ", (int) encrreq.encryptedrequest[i]);
			printf("\n");
			//	printf("Final Encryptd Message %s\n", encrreq.encryptedrequest);
			if ((encreply = alpha_1(encrreq, cl1)) == NULL) {
				clnt_perror(cl1, "call failed");
				exit(3);
			}
			break;
		case 2:
			printf("Enter the value :\n");
			scanf("%s", req.a.s);

			printf("Key used to encrypt Message :\n");

			for (i = 0; i < 8; i++) {
				printf("%03d ", (int) junkkey[i]);
			}
			memset(arguments, '\0', 96);
			memcpy(arguments, req.a.s, 68);
			memset(encryptedmsg, '\0', 96);
			memset(finalmsg, '\0', 156);
			printf("Arguments : %s\n", arguments);
			printf("Token at client: %s\n", junkkeytok);
			printf("Encrypted Token at Client:");
			for (i = 0; i < strlen(junkkeytok); i++)
				printf("%03d ", (int) junkkeytok[i]);
			printf("\n");

			R_EncryptPEMBlock(encryptedmsg, &encryptedmsglength, arguments, 68,
					junkkey, iv);

			memcpy(finalmsg, idclient, 8);
			memcpy(finalmsg + 8, idserver, 8);
			memcpy(finalmsg + 16, encryptedmsg, 96);
			memcpy(finalmsg + 112, junkkeytok, 44);
		//	memcpy(finalmsg + 112, "Dummytoken", 44);
			finalmsg[156] = '\0';

			memcpy(encrreq.encryptedrequest, finalmsg, 156);
			encrreq.encryptedrequest[156] = '\0';
			printf("Encrypted Message Request : ");

			for (i = 0; i < encrreq.encryptedrequestlength; i++)
				printf("%03d ", (int) encrreq.encryptedrequest[i]);
			printf("\n");
			//	printf("Final Encryptd Message %s\n", encrreq.encryptedrequest);
			if ((encreply = numeric_1(encrreq, cl1)) == NULL) {
				clnt_perror(cl1, "call failed");
				exit(3);
			}
			break;
		default:
			printf("Choice is invalid");
			exit(3);
		}

		if (encreply->encryptedreplylength != -1) {
			char junkstring[150];

			printf("Message Sent\n");
			printf("Clientid=%s\n", idclient);
			printf("Serverid=%s\n", idserver);
			//printf("Token=%s\n", req.token);
			printf("Input String=%s\n", req.a.s);
			printf("Input Length=%d\n", req.reqlen);
			printf("Message received\n");
			int resultlength;
			R_DecryptPEMBlock(junkstring, &resultlength,
					encreply->encryptedreply, encreply->encryptedreplylength,
					junkkey, iv);
			char cid[9], sid[9], data[69];
			memcpy(cid, junkstring, 8);
			memcpy(sid, junkstring + 8, 8);
			cid[8] = '\0';
			sid[8] = '\0';
			if (strncmp(cid,idclient,8) != 0 || strncmp(sid, idserver,8) != 0) {
				printf("Result is not from the original server!! Bogus Result\n");
				exit(2);
			}
			memcpy(data, junkstring + 16, 68);
			data[68] = '\0';

			printf("Junk Result after decryption: %s\n", junkstring);
			printf("Clientid: %s\n", cid);
			printf("Serverid: %s\n", sid);
			printf("Result: %s\n", data);
			printf("Result Length: %d\n", strlen(data));

		} else {
			char error[97];
			printf("Error received\n");
			memset(error, '\0', 96);
			printf("%d\n", encreply->encryptedreplylength);
			memcpy(error, encreply->encryptedreply, 96);
			error[96] = '\0';
			printf("%s", error);
		}
		clnt_destroy(cl1);

	} else {
		char junkerror[100];
		printf("Error received\n");
		printf("%d\n", encryptedreply->encry_length);
		memcpy(junkerror, encryptedreply->ency_msg,
				strlen(encryptedreply->ency_msg));
		junkerror[strlen(encryptedreply->ency_msg)] = '\0';
		printf("%s\n", junkerror);

	}
	clnt_destroy(cl); /* done with the handle */
	exit(0);
}
