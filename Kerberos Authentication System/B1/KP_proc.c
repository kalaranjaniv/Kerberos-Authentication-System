#include        <rpc/rpc.h>     /* standard RPC include file */
#include        "C1K.h"
#include 	<stdio.h>
#include 	<stdlib.h>
#include <string.h>

int KP_validator(char *id, char *publickey);
void keyGen(netReply *reply);
void token_builder(netReply *reply);
void replyBuilder(netReply *reply);

encryptedkeyreply* requestsessionkey_1(Request S) {
	unsigned char iv[8];
	memset(iv, '\0', 8);
	netReply reply;
	static encryptedkeyreply encryreply;

	printf("Inside Server 1 processing\n");
	printf("___________________________\n");
	printf("Session Request received with the following arguments\n");

	char junkclientid[9];
	char junkserverid[9];
	memcpy(junkclientid, S.C, 8);
	memcpy(junkserverid, S.S, 8);
	junkclientid[8] = '\0';
	junkserverid[8] = '\0';
	printf("Client id : %s\n", junkclientid);
	printf("Server id : %s\n", junkserverid);

	memcpy(reply.R.C, junkclientid, 8);
	memcpy(reply.R.S, junkserverid, 8);
	keyGen(&reply);
	token_builder(&reply);
	replyBuilder(&reply);
	char junkkey[9];
	char junkkeytok[9];
	memcpy(junkkey, reply.R.key, 8);
	memcpy(junkkeytok, reply.R.tok.key, 8);
	junkkey[8] = '\0';
	junkkeytok[8] = '\0';
	printf("Token : %s%s", junkclientid, junkserverid);
	int i;
	for (i = 0; i < 8; i++)
		printf("%03d", (int) junkkeytok[i]);
	printf("\n");
	printf("Response Sent\n");
	char responselocalarray[68];
	memset(responselocalarray, '\0', 48);
	memcpy(responselocalarray, reply.R.C, 8);
	memcpy(responselocalarray + 8, reply.R.S, 8);
	memcpy(responselocalarray + 16, reply.R.key, 8);

	char *clientpublickey = malloc(8 * sizeof(char));
	char *serverpublickey = malloc(8 * sizeof(char));
	int flag1 = KP_validator(junkserverid, serverpublickey);

	if (flag1 == 1) {
		char token[24];
		memcpy(token, reply.R.tok.C, 8);
		memcpy(token + 8, reply.R.tok.S, 8);
		memcpy(token + 16, reply.R.tok.key, 8);
		token[24]='\0';
		//printf("Token before Encrypting:%s\n",token);
		char encryptedtoken[44];
		int encryptedtokenlength;
		printf("Key used to encrypt token :%s\n", serverpublickey);
		R_EncryptPEMBlock(encryptedtoken, &encryptedtokenlength, token,
				24, serverpublickey, iv);
		memcpy(responselocalarray + 24, encryptedtoken, 44);
		printf("Encrypted token at Server:\n");
		for (i=0; i<encryptedtokenlength; i++)
				   printf("%03d ", (int)encryptedtoken[i]);
			        printf("\n");
		int flag = KP_validator(junkclientid, clientpublickey);

		if (flag == 1) {
			printf("Key used for encryption:%s\n", clientpublickey);
			responselocalarray[68] = '\0';
			R_EncryptPEMBlock(encryreply.ency_msg, &encryreply.encry_length,
					responselocalarray, 68,
					clientpublickey, iv);

			printf("Encrypted Message at Server:\n");
					for (i=0; i<encryreply.encry_length; i++)
							   printf("%03d ", (int)encryreply.ency_msg[i]);
						        printf("\n");

		} else {
			encryreply.encry_length = -1;
			memset(encryreply.ency_msg, '\0', 0);
			memcpy(encryreply.ency_msg, "invalid client", 20);
		}

	} else {
		encryreply.encry_length = -1;
		memset(encryreply.ency_msg, '\0', 0);
		memcpy(encryreply.ency_msg, "invalid server", 20);
	}

	return (&encryreply);
}
int KP_validator(char *id, char *publickey) {

	printf("Inside KP Validator\n");
	int flag = 0;
	FILE *fp;
	fp = fopen("DB.key", "r");
	char buff[16];
	memset(publickey, '\0', 8);
	if (fp != NULL) {
		int read = 0;
		while ((read = fread(buff, 1, 16, fp)) > 0) {
			if (strncmp(buff, id, 8) == 0) {
				memcpy(publickey, buff + 8, 8);
				publickey[8] = '\0';
				flag = 1;
				break;
			}

		}
		fclose(fp);
	}
	if (flag == 1) {
		printf("Public key Fetched : %s\n", publickey);
	} else {
		printf("No public key - Client/server is invalid\n");
	}
	return flag;
}
void keyGen(netReply *reply) {

	printf("Inside KeyGenerator\n");

	int i;
	char tem[8] = "tokengen";
	memset(tem, '\0', 8);
	FILE *dt, *popen();
	unsigned char text[128], randText[128];
	dt = popen("date; ps -e", "r");
	fread(text, 128, 1, dt);
	md5_calc(randText, text, 128);
	memcpy(tem, randText, 8);
	pclose(dt);
	memset(reply->R.key, '\0', 8);
	memcpy(reply->R.key, tem, 8);
	printf("Generated session key: ");
	for (i = 0; i < 8; i++)
		printf("%03d ", (int) tem[i]);
	printf("\n");

}
void token_builder(netReply *reply) {
	printf("Inside Token Builder : ");
	memcpy(reply->R.tok.C, reply->R.C, 8);
	memcpy(reply->R.tok.S, reply->R.S, 8);
	memcpy(reply->R.tok.key, reply->R.key, 8);

}
void replyBuilder(netReply *reply) {
	reply->replyLen = sizeof(struct netReply);
}
