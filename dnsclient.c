#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/* Manipulating stream of bytes */


unsigned char* encode_char(unsigned char* p, unsigned char val){
  *p = val;
  return p + 1;
}

unsigned char* encode_short(unsigned char* p, unsigned short val){
  unsigned short* sp = (unsigned short*) p;
  *sp = htons(val);
  return (unsigned char*)(sp + 1);
}

unsigned char* decode_char(unsigned char* p, unsigned char* s){
  *s = *p;
  return p + 1;
}

unsigned char* decode_short(unsigned char* p, unsigned short* s){
  unsigned short* sp = (unsigned short*)p;
  *s = ntohs(*sp);
  return (unsigned char*)(sp + 1);
}

unsigned char* decode_int(unsigned char* p, unsigned int* s){
  unsigned int* sp = (unsigned int*)p;
  *s = ntohl(*sp);
  return (unsigned char*)(sp + 1);
}

void dump_bytes(unsigned char *p, unsigned short n){
  for(unsigned short k = 0; k < n; k++){
    if(k % 16 == 0) printf("\n");
    else if (k % 8 == 0) printf("   ");
    printf("%02hhx ", p[k]);
  }
  printf("\n");
}

/* DNS header */

struct dns_header {
  unsigned short id;
  unsigned int qr:1;
  unsigned int opcode:4;
  unsigned int aa: 1;
  unsigned int tc:1;
  unsigned int rd:1;
  unsigned int ra:1;
  unsigned int z:3;
  unsigned int rcode:4;
  unsigned short qdcount;
  unsigned short ancount;
  unsigned short nscount;
  unsigned short arcount;
};

unsigned char* encode_header(unsigned char* p, struct dns_header* dh){
  p = encode_short(p, dh->id);
  unsigned short opts = 0;
  opts |= dh->qr << 15;
  opts |= dh->opcode << 11;
  opts |= dh->aa << 10;
  opts |= dh->tc << 9;
  opts |= dh->rd << 8;
  opts |= dh->ra << 7;
  opts |= dh->z << 4;
  opts |= dh->rcode;
  p = encode_short(p, opts);
  p = encode_short(p, dh->qdcount);
  p = encode_short(p, dh->ancount);
  p = encode_short(p, dh->nscount);
  p = encode_short(p, dh->arcount);
  return p;
}

struct dns_header* make_dns_header(){
  struct dns_header * dh = malloc(sizeof(struct dns_header));
  dh->id = 0xf78b;
  dh->qr = 0;
  dh->opcode = 0;
  dh->aa = 0;
  dh->tc = 0;
  dh->rd = 1;
  dh->ra = 0;
  dh->z = 0;
  dh->rcode = 0;
  dh->qdcount = 1;
  dh->ancount = 0;
  dh->nscount = 0;
  dh->arcount = 0;
  return dh;
}

unsigned char* decode_header(unsigned char* p, struct dns_header* dh){
  p = decode_short(p, &dh->id);
  unsigned short opts;
  p = decode_short(p, &opts);
  dh->qr = opts >> 15;
  dh->opcode = (opts >> 11) & 15;
  dh->aa = (opts >> 10) & 0x1;
  dh->tc = (opts >> 9) & 0x1;
  dh->rd = (opts >> 8) & 0x1;
  dh->ra = (opts >> 7) & 0x1;
  dh->z = (opts >> 4) & 7;
  dh->rcode = opts & 15;
  p = decode_short(p, &dh->qdcount);
  p = decode_short(p, &dh->ancount);
  p = decode_short(p, &dh->nscount);
  p = decode_short(p, &dh->arcount);
  return p;
}

void print_header(struct dns_header* dh){
  printf("ID: %x, ", dh->id);
  printf("Q/R: %u, ", dh->qr);
  printf("Opcode: %u\n", dh->opcode);
  printf("Aa: %u, ", dh->aa);
  printf("Tc: %u, ", dh->tc);
  printf("Rd: %u, ", dh->rd);
  printf("Ra: %u, ", dh->ra);
  printf("Z: %u, ", dh->z);
  printf("Rcode: %u\n", dh->rcode);
  printf("Qdcount: %u, ", dh->qdcount);
  printf("Ancount: %u, ", dh->ancount);
  printf("Nscount: %u, ", dh->nscount);
  printf("Arcount: %u\n", dh->arcount);
}

/* DNS types */

enum type {
  TYPE_A = 1,
  TYPE_NS = 2,
  TYPE_SOA = 6,
  TYPE_MX = 15,
  TYPE_TXT = 16,
  TYPE_AAAA = 28,
};

char* string_of_type(enum type t){
  switch(t){
  case TYPE_A: return "A";
  case TYPE_NS: return "NS";
  case TYPE_SOA: return "SOA";
  case TYPE_MX: return "MX";
  case TYPE_TXT: return "TXT";
  case TYPE_AAAA: return "AAAA";
  default: return "Unknown type";
  }
}


/* Decode a string */


unsigned char* decode_string(unsigned char* p0, unsigned char* p, unsigned char* out){
  unsigned char r = *p;
  if (r == 0){
    *out = 0;
    return p+1;
  } else if (r & 0xc0) {
    unsigned short ofs;
    p = decode_short(p, &ofs);
    ofs &= ~ 0xc000;
    decode_string(p0, p0 + ofs, out);
    return p;
  } else {
    p++;
    for(unsigned char i = 0; i < r; i++){
      *out = *p;
      out++; p++;
    }
    *out = '.';
    out++;
    return decode_string(p0, p, out);
  }
}

unsigned char* encode_string(unsigned char* p, char* str){
  unsigned char* plen = p;
  p++;
  int len = 0;
  while(*str){
    if(*str == '.'){
      *plen = len;
      len = 0;
      plen = p;
    } else {
      *p = *str;
      len++;
    }
    p++;
    str++;
  }
  *plen = len;
  p = encode_char(p, 0);
  return p;
}

/* DNS questions */

unsigned char* encode_question(unsigned char* p,
                               char* domain_name,
                               unsigned short type,
                               unsigned short class){
  p = encode_string(p, domain_name);
  p = encode_short(p, type);
  p = encode_short(p, class);
  return p;
}

unsigned char* decode_question(unsigned char* p0, unsigned char* p){
  unsigned char* domain = malloc(512);
  unsigned short type, class;
  p = decode_string(p0, p, domain);
  p = decode_short(p, &type);
  p = decode_short(p, &class);
  printf("Domain: '%s', Type: %s (%d), Class: %d\n",
         domain, string_of_type(type), type, class);
  free(domain);
  return p;
}

/* Decoding RRs */

unsigned char* decode_rr(unsigned char* p0, unsigned char* p){
  unsigned char* domain = malloc(512);
  unsigned short type, class, rdlength;
  unsigned int ttl;

  p = decode_string(p0, p, domain);
  p = decode_short(p, &type);
  p = decode_short(p, &class);
  p = decode_int(p, &ttl);
  p = decode_short(p, &rdlength);

  printf("Domain: '%s', Type: %s (%d), Class: %d, TTL: %d, RDlen: %d\n",
         domain, string_of_type(type), type, class, ttl, rdlength);
  free(domain);

  if(type == TYPE_SOA){
    unsigned char* mname = malloc(512);
    unsigned char* rname = malloc(512);
    unsigned int serial, refresh, retry, expire, minimum;
    p = decode_string(p0, p, mname);
    p = decode_string(p0, p, rname);
    p = decode_int(p, &serial);
    p = decode_int(p, &refresh);
    p = decode_int(p, &retry);
    p = decode_int(p, &expire);
    p = decode_int(p, &minimum);
    printf("MNAME: '%s', RNAME: '%s'\n", mname, rname);
    printf("Serial: %d, Refresh: %d, Retry: %d, Expire: %d, Minimum: %d\n",
           serial, refresh, retry, expire, minimum);
    free(mname);
    free(rname);
  } else if (type == TYPE_NS){
    unsigned char* str = malloc(512);
    p = decode_string(p0, p, str);
    printf("NS: %s\n", str);
    free(str);
  } else if (type == TYPE_MX){
    unsigned short pref;
    unsigned char* str = malloc(512);
    p = decode_short(p, &pref);
    p = decode_string(p0, p, str);
    printf("MX: %s (pref %d)\n", str, pref);
    free(str);
  } else if (type == TYPE_AAAA){
    printf("IPv6: ");
    unsigned char c;
    for(int i = 0; i < 16; i++){
      p = decode_char(p, &c);
      printf("%02hhx", c);
      if(i != 15) printf(":");
    }
    printf("\n");
  } else if (type == TYPE_A){
    printf("IPv4: ");
    unsigned char c;
    for(int i = 0; i < 4; i++){
      p = decode_char(p, &c);
      printf("%d", c);
      if(i != 3) printf(".");
    }
    printf("\n");
  } else if (type == TYPE_TXT){
    unsigned char* str = malloc(512);
    p = decode_string(p0, p, str);
    printf("TXT: %s\n", str);
    free(str);
  } else {
    dump_bytes(p, rdlength);
    p+=rdlength;
  }
  return p;
}

int make_dns_query(unsigned char* buf, char* domain_name, int type){
  unsigned char * p = buf;
  struct dns_header* dh = make_dns_header();
  p = encode_header(p, dh);
  p = encode_question(p, domain_name, type, 1);
  free(dh);
  return p - buf;
}

void decode_dns_packet(unsigned char* reply){
  struct dns_header dh;
  unsigned char* q = decode_header(reply, &dh);
  print_header(&dh);
  printf("*** Questions:\n");
  for(int i = 0; i < dh.qdcount; i++){
    printf("* Question %d/%d:\n", i+1, dh.qdcount);
    q = decode_question(reply, q);
  }
  printf("*** Answers:\n");
  for(int i = 0; i < dh.ancount; i++){
    printf("* Answer %d/%d:\n", i+1, dh.ancount);
    q = decode_rr(reply, q);
  }
  printf("*** Name server:\n");
  for(int i = 0; i < dh.nscount; i++){
    printf("* Name server %d/%d:\n", i+1, dh.nscount);
    q = decode_rr(reply, q);
  }
  printf("*** Authority records:\n");
  for(int i = 0; i < dh.arcount; i++){
    printf("* Authority record %d/%d:\n", i+1, dh.arcount);
    q = decode_rr(reply, q);
  }

}

int main(int argc, char** argv){
  if(argc < 3){
    printf("Usage: %s <domain> <type> [dns_server]\n", argv[0]);
    return 1;
  }

  char dns_server[20];
  if(argc > 3){
    strncpy(dns_server, argv[3], 19);
  } else {
    strncpy(dns_server, "127.0.0.53", 19);
  }

  unsigned char * buf = malloc(512);
  int nquery = make_dns_query(buf, argv[1], atoi(argv[2]));

  /* Create socket */
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if(sock == -1){
    perror("socket()");
    exit(errno);
  }

  /* Connect to server */
  struct sockaddr_in server;
  server.sin_family = AF_INET;
  server.sin_port = htons(53);
  server.sin_addr.s_addr = inet_addr(dns_server);
  if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0){
    perror("connect error");
    exit(errno);
  }

  /* Sending DNS query */
  if (send(sock, buf, nquery, 0) < 0){
    perror("send()");
    exit(errno);
  }
  free(buf);


  unsigned char reply[512] = {};
  int n = 0;
  if ((n = recv(sock, reply, 512, 0)) < 0){
    perror("recv()");
    exit(errno);
  }

  decode_dns_packet(reply);

  return 0;
}

