struct Token {
unsigned char C[8];
unsigned char S[8]; 
unsigned char key[8];
};

struct reply
{
unsigned char C[8];
unsigned char S[8]; 
unsigned char key[8];
struct Token tok;
};
struct netReply {
int replyLen; 
struct reply R;
};
struct Request {
int requestLen; 
unsigned char C[8];
unsigned char S[8]; 
};

struct encryptedkeyreply
{
int encry_length;
char ency_msg[300];
};

program CK_PROG {
	version CK_VERS {
		encryptedkeyreply REQUESTSESSIONKEY(Request S) = 1;
		} = 1; /* version number */
	} = 0x31007199; /*0x34243542;  program number should be large & unique */

