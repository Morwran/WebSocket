#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include "websocket.h"
#include <sys/sendfile.h>
#include <fcntl.h>
#include <stdbool.h>
//#include <openssl/sha.h>

#ifdef TESTING
	#include <math.h>
#endif

#define SERV_PORT 80
#define LISTENQ 5
#define BUFSIZE 1024
#define SW_BUF 65552
#define ROOT_NAME "index.html"
#define ROOT_PATH "www/"

char buffer[BUFSIZE] = {0};

// #define LOG_OUT stderr

#define WrnPrint(fmt, args...) do {\
	fprintf(stderr,"[%s] -> WRN: ", gettime());\
	fprintf(stderr, fmt, ##args);\
	fprintf(stderr,"\n");\
}while(0)

#define LogPrint(fmt, args...) do {\
	fprintf(stdout,"[%s] -> INFO: ", gettime());\
	fprintf(stdout, fmt, ##args);\
	fprintf(stdout,"\n");\
}while(0)	

#define print_and_exit(fmt, args...) do {\
	fprintf(stderr,"[%s] -> Err: ", gettime());\
	fprintf(stderr, fmt, ##args);\
	fprintf(stderr,"\n");\
	exit(-1);\
}while(0)

static char * gettime(){
	time_t t = time (NULL);
	char *tp = ctime (&t);
	tp[strlen(tp)-1]='\0';
	return tp;
}



typedef struct
 {
   uint32_t state[5];
   uint32_t count[2];
   unsigned char buffer[64];
 } SHA1_CTX;


/////////////////////////////////////////////// SHA1 /////////////////////////////////////////////////////////////
void SHA1Transform( uint32_t state[5], const unsigned char buffer[64])
 {
    uint32_t a, b, c, d, e;
    typedef union
     {
       unsigned char c[64];
       uint32_t l[16];
     } CHAR64LONG16;

    CHAR64LONG16 block[1];    
    memcpy(block, buffer, 64);

    a = state[0]; b = state[1]; c = state[2]; d = state[3]; e = state[4];

    R0(a, b, c, d, e, 0); R0(e, a, b, c, d, 1); R0(d, e, a, b, c, 2); R0(c, d, e, a, b, 3);
    R0(b, c, d, e, a, 4); R0(a, b, c, d, e, 5); R0(e, a, b, c, d, 6); R0(d, e, a, b, c, 7);
    R0(c, d, e, a, b, 8); R0(b, c, d, e, a, 9); R0(a, b, c, d, e, 10); R0(e, a, b, c, d, 11);
    R0(d, e, a, b, c, 12); R0(c, d, e, a, b, 13); R0(b, c, d, e, a, 14); R0(a, b, c, d, e, 15);
    R1(e, a, b, c, d, 16); R1(d, e, a, b, c, 17); R1(c, d, e, a, b, 18); R1(b, c, d, e, a, 19);
    R2(a, b, c, d, e, 20); R2(e, a, b, c, d, 21); R2(d, e, a, b, c, 22); R2(c, d, e, a, b, 23);
    R2(b, c, d, e, a, 24); R2(a, b, c, d, e, 25); R2(e, a, b, c, d, 26); R2(d, e, a, b, c, 27);
    R2(c, d, e, a, b, 28); R2(b, c, d, e, a, 29); R2(a, b, c, d, e, 30); R2(e, a, b, c, d, 31);
    R2(d, e, a, b, c, 32); R2(c, d, e, a, b, 33); R2(b, c, d, e, a, 34); R2(a, b, c, d, e, 35);
    R2(e, a, b, c, d, 36); R2(d, e, a, b, c, 37); R2(c, d, e, a, b, 38); R2(b, c, d, e, a, 39);
    R3(a, b, c, d, e, 40); R3(e, a, b, c, d, 41); R3(d, e, a, b, c, 42); R3(c, d, e, a, b, 43);
    R3(b, c, d, e, a, 44); R3(a, b, c, d, e, 45); R3(e, a, b, c, d, 46); R3(d, e, a, b, c, 47);
    R3(c, d, e, a, b, 48); R3(b, c, d, e, a, 49); R3(a, b, c, d, e, 50); R3(e, a, b, c, d, 51);
    R3(d, e, a, b, c, 52); R3(c, d, e, a, b, 53); R3(b, c, d, e, a, 54); R3(a, b, c, d, e, 55);
    R3(e, a, b, c, d, 56); R3(d, e, a, b, c, 57); R3(c, d, e, a, b, 58); R3(b, c, d, e, a, 59);
    R4(a, b, c, d, e, 60); R4(e, a, b, c, d, 61); R4(d, e, a, b, c, 62); R4(c, d, e, a, b, 63);
    R4(b, c, d, e, a, 64); R4(a, b, c, d, e, 65); R4(e, a, b, c, d, 66); R4(d, e, a, b, c, 67);
    R4(c, d, e, a, b, 68); R4(b, c, d, e, a, 69); R4(a, b, c, d, e, 70); R4(e, a, b, c, d, 71);
    R4(d, e, a, b, c, 72); R4(c, d, e, a, b, 73); R4(b, c, d, e, a, 74); R4(a, b, c, d, e, 75);
    R4(e, a, b, c, d, 76); R4(d, e, a, b, c, 77); R4(c, d, e, a, b, 78); R4(b, c, d, e, a, 79);

    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
    a = b = c = d = e = 0;
    memset(block, 0, sizeof(block));
 }


void SHA1Init( SHA1_CTX * context)
 {
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
 }


void SHA1Update( SHA1_CTX * context, const unsigned char *data, uint32_t len)
 {
    uint32_t i;
    uint32_t j;

    j = context->count[0];
    if ((context->count[0] += len << 3) < j) context->count[1]++;

    context->count[1] += (len >> 29);
    j = (j >> 3) & 63;
    if((j + len) > 63)
     {
       memcpy(&context->buffer[j], data, (i = 64 - j));

       SHA1Transform(context->state, context->buffer);
       for(; i + 63 < len; i += 64)
        {
          SHA1Transform(context->state, &data[i]);
        }

       j = 0;
     }

    else i = 0;

    memcpy(&context->buffer[j], &data[i], len - i);
 }


void SHA1Final( unsigned char digest[20], SHA1_CTX * context)
 {
    unsigned i;
    unsigned char c, finalcount[8];

    for(i = 0; i < 8; i++)
     {
       finalcount[i] = (unsigned char) ((context->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);     
     }

    c = 0200;
    SHA1Update(context, &c, 1);

    while((context->count[0] & 504) != 448)
     {
       c = 0000;
       SHA1Update(context, &c, 1);
     }

    SHA1Update(context, finalcount, 8); 

    for(i = 0; i < 20; i++)
     {
       digest[i] = (unsigned char) ((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
     }

    memset(context, 0, sizeof(*context));
    memset(&finalcount, 0, sizeof(finalcount));
 }


void SHA1(unsigned char *hash_out, const char *str, unsigned int len)
 {
    SHA1_CTX ctx;
    unsigned int ii;
    SHA1Init(&ctx);
    for (ii=0; ii<len; ii+=1) SHA1Update(&ctx, (const unsigned char*)str + ii, 1);
    SHA1Final((unsigned char *)hash_out, &ctx);
    hash_out[20] = 0;
 }



static int base64_encode(unsigned char sha_key_in[], unsigned char base64_key_out[], int len)
 {
   int idx, idx2, blks, left_over;

   blks = (len / 3) * 3;
   for(idx=0, idx2=0; idx < blks; idx += 3, idx2 += 4) 
    {
      base64_key_out[idx2] = charset[sha_key_in[idx] >> 2];
      base64_key_out[idx2+1] = charset[((sha_key_in[idx] & 0x03) << 4) + (sha_key_in[idx+1] >> 4)];
      base64_key_out[idx2+2] = charset[((sha_key_in[idx+1] & 0x0f) << 2) + (sha_key_in[idx+2] >> 6)];
      base64_key_out[idx2+3] = charset[sha_key_in[idx+2] & 0x3F];
    }

   left_over = len % 3;

   if(left_over == 1) 
    {
      base64_key_out[idx2] = charset[sha_key_in[idx] >> 2];
      base64_key_out[idx2+1] = charset[(sha_key_in[idx] & 0x03) << 4];
      base64_key_out[idx2+2] = '=';
      base64_key_out[idx2+3] = '=';
      idx2 += 4;
    }

   else if(left_over == 2) 
    {
      base64_key_out[idx2] = charset[sha_key_in[idx] >> 2];
      base64_key_out[idx2+1] = charset[((sha_key_in[idx] & 0x03) << 4) + (sha_key_in[idx+1] >> 4)];
      base64_key_out[idx2+2] = charset[(sha_key_in[idx+1] & 0x0F) << 2];
      base64_key_out[idx2+3] = '=';
      idx2 += 4;
    }

   base64_key_out[idx2] = 0;
   return(idx2);
 }

static void send_file(int fd_out, const char *path){
	struct stat sb;
	int fd_in;
	int snd_cnt = 0;

	fd_in = open (path, O_RDONLY);

	if (fd_in == -1) {
		WrnPrint("Open file %s is fail. %s", path, strerror(errno));
		return;
	}

	if (fstat (fd_in, &sb) == -1) {
		WrnPrint("Stat file %s is fail. %s", path, strerror(errno));
		close(fd_in);
		return;	
	}

	if((snd_cnt=sendfile(fd_out, fd_in, NULL, sb.st_size)) == -1){

		WrnPrint("Send file %s is fail. %s", path, strerror(errno));
		close(fd_in);
		return;
	}
	LogPrint("Response %s Send %d bytes", path, snd_cnt);
	close(fd_in);

}

static void send_ws_text_msg(int fd, const char *msg)
{
	size_t msg_size = strlen(msg);
	unsigned char *out_buf = NULL;
	size_t size_send = 0;

	out_buf = (msg_size < 126) ? calloc(1, msg_size + 2) : calloc(1, msg_size + 4);

	if(!out_buf){
			WrnPrint("Send msg is fail. %s", strerror(errno));
			return;
	}

	out_buf[0] = 0x81;
	
	if(msg_size < 126){		
		out_buf[1] = msg_size;
		size_send = msg_size + 2;
		memcpy(&out_buf[2], msg, msg_size);
	}
	else{
		out_buf[1] = 126;
		out_buf[3] = msg_size & 0xFF;
		out_buf[2] = (msg_size >> 8) & 0xFF;
		memcpy(&out_buf[4], msg, msg_size);
		size_send = msg_size + 4;
	}

	for(int i =0; i < size_send; printf("%x ", out_buf[i++]));
	printf("\n");	
	if(send(fd, out_buf, size_send, 0) == -1){
		WrnPrint("Send msg is fail. %s", strerror(errno));
	}

	if(out_buf){
		free(out_buf);
		out_buf = NULL;
	}

}

#ifdef TESTING
static int sin_dump(int t){
	int A = 2;
	double S = A*sin(t);
	printf("S %.2f\n", S);
	return (int)(S*100);
}
#endif

static void ws_proc(int fd){
		LogPrint("WS Process start for Client ID %d\n", fd);
		unsigned char inbuf[SW_BUF];
		bool is_start_byte_tr = false;
		fd_set readfds;
		int ret = -1;
		struct timeval tv;

#ifdef TESTING
		int t = 0;
#endif

		for(;;){
			FD_ZERO(&readfds);
			FD_SET(fd, &readfds);

			tv.tv_sec = 1;
			tv.tv_usec = 0;

			if ((ret = select(fd + 1, &readfds, (fd_set *) NULL, (fd_set *) NULL, &tv)) < 0) {
				LogPrint("Can't waited socket: %s", strerror(errno));
        break;
      }

      if (FD_ISSET(fd, &readfds)) {

				memset(inbuf, 0, SW_BUF);

				long rcv_b = read(fd, inbuf, SW_BUF - 1);

				if(rcv_b < 0){
					WrnPrint("Connection closed. %s", strerror(errno));
					return;
				}

				if(rcv_b > 0){
					unsigned char masking_key[4] = {0};
      	  unsigned char opcode;
      	  unsigned short payload_len;
      	  printf("RCV: 0x%X%X\n", inbuf[0], inbuf[1]);
      	  opcode = WS_OPCODE_RCVD(inbuf);
      	  printf("FIN: 0x%02X\n", WS_FIN_RCVD(inbuf));
      	  printf("RSV1: 0x%02X\n", WS_RCV1_RCVD(inbuf));
      	  printf("RSV2: 0x%02X\n", WS_RCV2_RCVD(inbuf));
      	  printf("RSV3: 0x%02X\n", WS_RCV3_RCVD(inbuf));
      	  printf("Opcode: 0x%02X\n", opcode);
	
      	  payload_len = WS_LENGTH_RCVD(inbuf);
      	  printf("payload_len: %u 0x%x\n", payload_len, payload_len);
      	  printf("Mask: 0x%02x\n", WS_MSK_RCVD(inbuf));
	
      	  if(opcode == WS_CLOSING_FRAME) // closing connection
      	  {
      	   		WrnPrint("Connection closed by Client ID %d", fd);
							return;
      	  }
	
      	  if(opcode == WS_TEXT_FRAME) // receive text from client
      	  {
      	   		
      	   		LogPrint("Received TEXT Frame from Client ID %d", fd);
      	   		if(payload_len < 126){
      	   			memcpy(masking_key, &inbuf[2], sizeof masking_key);
	
      	   		}
      	   		
      	   		// thus this is not a lenght but this is a code means 
      	   		// that length is more then 125 bytes 
      	   		if(payload_len == 126){
      	   			// unsigned short payload_len_s = *(unsigned short *)&inbuf[2];
      	   			payload_len = WS_LENGTH126_RCVD(inbuf);
      	   			printf("payload_len: %u 0x%x\n", payload_len, payload_len);
      	   			memcpy(masking_key, &inbuf[4], sizeof masking_key);
	
      	   		}
      	   		char *payload = calloc(1, payload_len + 1);
      	   		unsigned int i = (payload_len < 126) ? 6 : 8, pl = 0;
      	      for(; pl < payload_len; i++, pl++)
      	      {
      	         	payload[pl] = inbuf[i]^masking_key[pl % 4]; 
      	      }
	
      	      payload[payload_len] = '\0';
					         		
      	   		printf("PL: %s\n", payload);
	
      	   		if(!strcmp(payload, "start tr"))
      	   			is_start_byte_tr = true;
      	   		if(!strcmp(payload, "stop tr"))
      	   			is_start_byte_tr = false;
	
      	   		send_ws_text_msg(fd, payload);
	
      	   		free(payload);
      	  		payload = NULL;
	
      	  }
	
				}
			}

			if(is_start_byte_tr){
#ifdef TESTING
				char dump_buf[10];
				snprintf(dump_buf, sizeof dump_buf, "%d", sin_dump(t));
				send_ws_text_msg(fd, dump_buf);
				printf("is_start_byte_tr %u\n", is_start_byte_tr);
				t++;
#endif
			}
		}
		LogPrint("Leave ws proc\n");
}

static void route(int fd, const char * buf){
	printf("RCV: %s\n", buf);

	if(strstr(buf, "GET / ")) 
	{
		LogPrint("GET / ");
		if(send(fd, response, (int)strlen(response), MSG_NOSIGNAL) == -1){
			WrnPrint("Send response is fail. %s", strerror(errno));
			return;
		}
		size_t len = strlen(ROOT_PATH) + strlen(ROOT_NAME) + 1;
		char *path = calloc(1, len);
		if(!path){
			WrnPrint("Alloc mem err. %s", strerror(errno));
			return;
		}
		snprintf(path, len, "%s%s", ROOT_PATH, ROOT_NAME);
		send_file(fd, path);
		free(path);
		path = NULL;
	}
	else if(strstr(buf, "GET /ws ")) 
	{

		char * ws_key_cli_str = strstr(buf, WS_KEY);
		if(ws_key_cli_str){
			ws_key_cli_str += strlen(WS_KEY);
			char *ws_key_cli = strsep(&ws_key_cli_str, "\r\n");
			size_t hash_len = strlen(ws_key_cli)+strlen(GUIDKey)+1;
			char *hash_key = calloc(1, hash_len);
			if(!hash_key){
				WrnPrint("Alloc mem err. %s", strerror(errno));
				return;
			}
			snprintf(hash_key, hash_len, "%s%s", ws_key_cli, GUIDKey);

			printf("__hash_key:%s:\n", hash_key);

			unsigned char hash_sha1[SHA_DIGEST_LENGTH];
			SHA1(hash_sha1, hash_key, strlen(hash_key));
			free(hash_key);
			hash_key = NULL;

			unsigned char key_out[64] = {0};
      base64_encode(hash_sha1, key_out, sizeof hash_sha1);

			size_t len_resp = strlen(response_ws) + strlen(key_out) + 8;
			printf("__len resp: %lu, len key: %lu %lu, len: %lu\n", 
			strlen(response_ws), strlen(key_out), sizeof key_out, len_resp);
			printf("__key out(%s):\n", key_out);
			char *resp = calloc(1, len_resp);
			if(!resp){
				WrnPrint("Alloc mem err. %s", strerror(errno));
				return;
			}

			snprintf(resp, len_resp, "%s%s\r\n\r\n", response_ws, key_out);
			printf("__resp: %s", resp);
			if(send(fd, resp, (int)strlen(resp), MSG_NOSIGNAL) == -1){
				WrnPrint("Send response is fail. %s", strerror(errno));
				return;
			}

			free(resp);
			resp = NULL;

			ws_proc(fd);
			LogPrint("Leave Client ID %d\n", fd);

		}

	}
	else{
		if(send(fd, response_403, (int)strlen(response_403), MSG_NOSIGNAL) == -1){
			WrnPrint("Send response_403 is fail. %s", strerror(errno));
			return;
		}
	}
}

int main(int argc, char const *argv[])
{
	/* code */	
	int listenfd, connfd;
	pid_t child_pid;
	struct sockaddr_in addr_cli, addr_srv;

	socklen_t sin_len = sizeof(addr_cli);
	listenfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(listenfd < 0)
		print_and_exit("Fail soc open! %s", strerror(errno));
	//int one = 1;
	//setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));
	memset(&addr_srv, 0, sizeof(addr_srv));
	addr_srv.sin_family = AF_INET;
	addr_srv.sin_addr.s_addr = INADDR_ANY;
	addr_srv.sin_port = htons(SERV_PORT);
	
	if(bind(listenfd, (struct sockaddr *)&addr_srv, sizeof(addr_srv)) == -1){
		close(listenfd);
		print_and_exit("Fail soc bind! %s", strerror(errno));		
	}

	if(listen(listenfd,LISTENQ) < 0){
		close(listenfd);
		print_and_exit("Fail soc listen! %s", strerror(errno));
	}

	LogPrint("Server start at port: %d, addr %s", SERV_PORT, inet_ntoa(addr_srv.sin_addr));

#ifdef TESTING
	LogPrint("APP UNDER TESTS!\n");
#endif	

	for(;;){
		if((connfd=accept(listenfd, (struct sockaddr *)&addr_cli, &sin_len)) < 0){
			continue;
		}

		if((child_pid = fork()) == 0) {
			close(listenfd);
			LogPrint("Connect addr %s", inet_ntoa(addr_cli.sin_addr));
			memset(buffer, 0, BUFSIZE);

			if(read(connfd, buffer, BUFSIZE - 1) == -1){
				close(connfd);
				print_and_exit("Fail soc read! %s", strerror(errno));
			}
			
			route(connfd, buffer);
			exit(0);
		}

		close(connfd);
	}

	return 0;
}