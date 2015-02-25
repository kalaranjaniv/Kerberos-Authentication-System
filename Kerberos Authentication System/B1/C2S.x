struct args {	
	unsigned char s[68];
	}; /* ; required */
struct request
{
unsigned char C[8];
unsigned char S[8];
struct args a;
unsigned char token[44];
int reqlen;
};
struct response {
	unsigned char C[8];
	unsigned char S[8];	
	unsigned char rep[68];
	}; /* ; required */
	

struct encryptedmsg
{
int encryptedrequestlength;
unsigned char encryptedrequest[156];
};

struct encryptedreply
{
int encryptedreplylength;
unsigned char encryptedreply[120];
};

program CS_PROG {
	version CS_VERS {
		encryptedreply ALPHA (encryptedmsg r) = 1;
		encryptedreply NUMERIC (encryptedmsg r) = 2;
		} = 1; /* version number */
	} = 0x31007198; /*0x34243542;  program number should be large & unique */
	