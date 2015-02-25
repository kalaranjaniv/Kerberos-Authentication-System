#
BIN_ALL = KEYSERVER SERVER CLIENT_ALL
GEN_C1K = C1K_xdr.c C1K_clnt.c C1K_svc.c C1K.h
GEN_C2P = C2S_xdr.c C2S_clnt.c C2S_svc.c C2S.h
GEN_ALL = CLIENT_ALL
LIB = -lnsl rsaref.a -lmd5
CFLAGS = -I.. -O 
CC = gcc -DDEBUG

all:$(GEN_ALL) $(BIN_ALL)

$(GEN_C1K):         C1K.x
		rpcgen -N C1K.x

$(GEN_C2P):         C2S.x
		rpcgen -N C2S.x

KEYSERVER:         C1K_svc.o C1K_xdr.o proc.o
		$(CC) -o $@ KP_proc.c C1K_svc.o C1K_xdr.o $(LIB)

client.o:       C1P.c C1K.h

proc.o:         KP_proc.c C1K.h

clean:
		rm -f $(GEN_C1K) *.o $(BIN_C1K)
		rm -f $(GEN_C2P) *.o $(BIN_C2P)
		rm -f $(GEN_ALL) *.o $(BIN_ALL)

SERVER:         C2S_svc.o C2S_xdr.o proc1.o
		$(CC) -o $@ SP_proc.c C2S_svc.o C2S_xdr.o $(LIB)


client1.o:       C2P.c C2S.h

proc1.o:         SP_proc.c C2S.h

CLIENT_ALL: 		 C1K_xdr.o C2S_xdr.o C2S_clnt.c C1K_clnt.c
			$(CC) -o $@ CP.c C1K_xdr.o C2S_xdr.o C2S_clnt.c C1K_clnt.c $(LIB)
