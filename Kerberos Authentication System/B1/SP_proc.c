#include        <rpc/rpc.h>     /* standard RPC include file */
#include        "C2S.h"
#include 	<stdio.h>
#include 	<stdlib.h>
#include <ctype.h>
#include <string.h>
#include "Skey.h"
int SP_validator(char *clientid, char *serverid, char *ecryptedtoken,
		char *sessionkey);
void replyBuilder(response *resp1, char *result,encryptedreply *encrreply,char *sessionkey,char *argserver,char *argclient);

encryptedreply* alpha_1(encryptedmsg encrmsg) {

	char line[68];
	static struct response resp1;
	int i, j;
	char idclient[8];
	char idserver[8];
	char token[44];

	printf("Encrypted Message Request received at server : ");
//	printf("%s\n", encrmsg.encryptedrequest);
	for (i = 0; i < strlen(encrmsg.encryptedrequest); i++) {
		printf("%03d ", (int) encrmsg.encryptedrequest[i]);

	}

	printf("\n");
	char sessionkey[8];
	char encryptedmsg[96];
	char argserver[8];
	char argclient[8];
	memset(idclient, '\0', 8);
	memset(idserver, '\0', 8);
	memset(encryptedmsg, '\0', 96);
	memset(token, '\0', 44);
	memcpy(idclient, encrmsg.encryptedrequest, 8);
	idclient[8] = '\0';
	strcpy(argclient, idclient);
	printf("Client id %s\n", idclient);
	memcpy(idserver, encrmsg.encryptedrequest + 8, 8);
	idserver[8] = '\0';
	strcpy(argserver, idserver);
	printf("Server id %s\n", idserver);
	memcpy(encryptedmsg, encrmsg.encryptedrequest + 16, 96);
	encryptedmsg[96] = '\0';
//	printf("Encypted Arguments: %s\n", encryptedmsg);
	memcpy(token, encrmsg.encryptedrequest + 112, 44);
	token[44] = '\0';
	printf("Encypted token: %s\n", token);

	printf("Encrypted Token at Server :");
	for (i = 0; i < strlen(token); i++)
		printf("%03d ", (int) token[i]);
	printf("\n");
	int flag = SP_validator(argclient, argserver, token, sessionkey);
	sessionkey[8] = '\0';
	int keyindex = 0;
	static struct encryptedreply encrreply;
	if (flag == 1) {
		unsigned char iv[8];
		memset(iv, '\0', 8);
		char decryptedmsg[68];
		int decryptedmsglength;
		printf("Key used for decryption of Message:\n");
		for (keyindex = 0; keyindex < 8; keyindex++) {
			printf("%03d ", (int) sessionkey[keyindex]);
		}

		R_DecryptPEMBlock(decryptedmsg, &decryptedmsglength, encryptedmsg, 96,
				sessionkey, iv);

		decryptedmsg[decryptedmsglength] = '\0';
		//	printf("decryptedmsg:%s\n", decryptedmsg);
		memset(line, '\0', 68);
		memcpy(line, decryptedmsg, 68);
		line[68] = '\0';
		printf("Inside Server 2 processing\n");
		printf("___________________________\n");
		printf("Message Received\n");
		printf("%s\n", line);
		for (i = 0; line[i] != '\0'; ++i) {
			while (!((line[i] >= 'a' && line[i] <= 'z')
					|| (line[i] >= 'A' && line[i] <= 'Z' || line[i] == '\0'))) {
				for (j = i; line[j] != '\0'; ++j) {
					line[j] = line[j + 1];
				}
				line[j] = '\0';
			}
		}

		replyBuilder(&resp1, line, &encrreply,sessionkey,argserver,argclient);
		printf("Response Sent\n");
		printf("String: %s\n", resp1.rep);
		printf("Length: %d\n", strlen(resp1.rep));
		return (&encrreply);
	} else {

			printf("Error:Data not matching with the token data");
			memset(encrreply.encryptedreply, '\0', 96);
			encrreply.encryptedreplylength = -1;
			memcpy(encrreply.encryptedreply, "Error:Data not matching with the token data", 96);
			return (&encrreply);
	}
}

encryptedreply* numeric_1(encryptedmsg encrmsg) {

	char line[68];
	static struct response resp1;
	int i, j = 0;
	char idclient[8];
	char idserver[8];
	char token[44];

	printf("Encrypted Message Request received at server : ");
//	printf("%s\n", encrmsg.encryptedrequest);
	for (i = 0; i < strlen(encrmsg.encryptedrequest); i++) {
		printf("%03d ", (int) encrmsg.encryptedrequest[i]);

	}

	printf("\n");
	char sessionkey[8];
	char encryptedmsg[96];
	char argserver[8];
	char argclient[8];
	memset(idclient, '\0', 8);
	memset(idserver, '\0', 8);
	memset(encryptedmsg, '\0', 96);
	memset(token, '\0', 44);
	memcpy(idclient, encrmsg.encryptedrequest, 8);
	idclient[8] = '\0';
	strcpy(argclient, idclient);
	printf("Client id %s\n", idclient);
	memcpy(idserver, encrmsg.encryptedrequest + 8, 8);
	idserver[8] = '\0';
	strcpy(argserver, idserver);
	printf("Server id %s\n", idserver);
	memcpy(encryptedmsg, encrmsg.encryptedrequest + 16, 96);
	encryptedmsg[96] = '\0';
//	printf("Encypted Arguments: %s\n", encryptedmsg);
	memcpy(token, encrmsg.encryptedrequest + 112, 44);
	token[44] = '\0';
//	printf("Encypted token: %s\n", token);

	printf("Encrypted Token at Server :");
	for (i = 0; i < strlen(token); i++)
		printf("%03d ", (int) token[i]);
	printf("\n");
	int flag = SP_validator(argclient, argserver, token, sessionkey);
	sessionkey[8] = '\0';
	int keyindex = 0;
	static struct encryptedreply encrreply;
	if (flag == 1) {
		unsigned char iv[8];
		memset(iv, '\0', 8);
		char decryptedmsg[68];
		int decryptedmsglength;
		printf("Key used for decryption of Message:\n");
		for (keyindex = 0; keyindex < 8; keyindex++) {
			printf("%03d ", (int) sessionkey[keyindex]);
		}

		R_DecryptPEMBlock(decryptedmsg, &decryptedmsglength, encryptedmsg, 96,
				sessionkey, iv);

		decryptedmsg[decryptedmsglength] = '\0';
		//printf("decryptedmsg:%s\n", decryptedmsg);
		memset(line, '\0', 68);
		memcpy(line, decryptedmsg, decryptedmsglength);
		line[decryptedmsglength] = '\0';
		printf("Inside Server 2 processing\n");
		printf("___________________________\n");
		printf("Message Received\n");
		printf("%s\n", line);
		char numeric[68];
		memset(numeric, '\0', decryptedmsglength);
		for (i = 0; line[i] != '\0'; ++i) {
			if (isdigit(line[i])) {
				numeric[j] = line[i];
				j++;
			}

		}
		numeric[j] = '\0';


		replyBuilder(&resp1, numeric, &encrreply,sessionkey,argserver,argclient);

		printf("Response Sent\n");
		printf("String: %s\n", resp1.rep);
		printf("Length: %d\n", strlen(resp1.rep));
		return (&encrreply);
	} else {

		printf("Error:Data not matching with the token data");
		memset(encrreply.encryptedreply, '\0', 96);
		encrreply.encryptedreplylength = -1;
		memcpy(encrreply.encryptedreply, "Error:Data not matching with the token data", 96);
		return (&encrreply);
}

}

int SP_validator(char *clientid, char *serverid, char *ecryptedtoken,
		char *sessionkey) {
	printf("Inside SP validator\n");
	unsigned char iv[8];
	memset(iv, '\0', 8);
	char decryptedtoken[24];
	int decryptedtokenlength;

	printf("\nKey used for decryption of the token: %s\n", key);
	R_DecryptPEMBlock(decryptedtoken, &decryptedtokenlength, ecryptedtoken, 44,
			key, iv);

	//printf("Decrypted token %s\n", decryptedtoken);

	if (strncmp(decryptedtoken, clientid, 8) == 0
			&& strncmp(decryptedtoken + 8, serverid, 8) == 0) {
		memcpy(sessionkey, decryptedtoken + 16, 8);
		printf("Exit of SP server\n");
		return 1;
	} else {
		printf("Data is not matching\n");
		printf("Exit of SP server\n");
		return 0;
	}

}
void replyBuilder(response *resp1, char *result,encryptedreply *encrreply,char *sessionkey,char *argserver,char *argclient) {
	unsigned char iv[8];
	memset(iv, '\0', 8);
	memset(resp1->rep, '\0', 68);
	memset(resp1->C,'\0',8);
	memset(resp1->S,'\0',8);

	memcpy(resp1->rep, result, strlen(result));
	memcpy(resp1->C, argclient, 8);
	memcpy(resp1->S, argserver, 8);
	char msgtoencrypt[88];
	memcpy(msgtoencrypt, (unsigned char*)resp1, 88);
	printf("Message to Encrypt: %s\n",msgtoencrypt);
	int encryptedtokenlength;
	R_EncryptPEMBlock(encrreply->encryptedreply, &encrreply->encryptedreplylength, msgtoencrypt,88,
			sessionkey, iv);
}
