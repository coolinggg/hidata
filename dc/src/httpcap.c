#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
// #include "MqDCClient.h"
// #include "suffixfilter.h"
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 65535//1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* CR LF define */
#define CR (u_char) 13
#define LF (u_char) 10


// static ZmqDCClient *dcClient;

FILE * ffp;

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IPv6 header */

/* IPv4 header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/* define http header segment state , the state just recode context infomation */
#define HS_HOST         1
#define HS_USER_AGENT   2
#define HS_REFERER      3
#define HS_COOKIE       4

/* http request key info */
struct http_request_kinfo{
        u_char                  *uri_start;
	u_char                  *uri_end;
	u_char                  *host_start;
	u_char                  *host_end;
	u_char                  *ua_start;
	u_char                  *ua_end;
	u_char                  *referer_start;
	u_char                  *referer_end;
	u_char                  *cookies_start;
	u_char                  *cookies_end;
	u_int                   sip;           /* soure ip address is unsigned int, max is 4294967295 */
	u_int                   dip;           /* dst ip address is unsigened int, max is 4294967295 */
	time_t                  sec;           /* seconds from 1900 */
	time_t                  usec;          /* micro-seconds */
	char                    timestamp[25];
	const u_char            *content;      /* tcp payload */
	u_int                   len;           /* tcp payload length */

	/* record context */
        int                  headerstate;
};


/*int 
send2mq(char *str);*/

void
int2str(u_int num, char **str);

void
truct2json(struct http_request_kinfo *httprequest, char *str);

int 
http_parse_request(struct http_request_kinfo *httprequest);

void
got_packet(const struct pcap_pkthdr *header, const u_char *packet);
//got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

#define str3_cmp(m, c0, c1, c2, c3)                                       \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)

#define str3Ocmp(m, c0, c1, c2, c3)                                       \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)

#define str4cmp(m, c0, c1, c2, c3)                                        \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)

#define str5cmp(m, c0, c1, c2, c3, c4)                                    \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
		        && m[4] == c4

#define str6cmp(m, c0, c1, c2, c3, c4, c5)                                \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
	&& (((uint32_t *) m)[1] & 0xffff) == ((c5 << 8) | c4)

#define str7cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                       \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
        && ((uint32_t *) m)[1] == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4)

#define str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                        \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
        && ((uint32_t *) m)[1] == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4)

#define str9cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8)                    \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
        && ((uint32_t *) m)[1] == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4)  \
	&& m[8] == c8


void
int2str(u_int num, char **str)
{
	int i = 0;
	char temp[16];
	while(num)  
	{  
	    temp[i] = num % 10 + '0';   //取模运算得到从后往前的每一个数字变成字符  
	    num = num / 10;  
	    i++;  
	}  
	temp[i] = 0;    //字符串结束标志  
						          
	i = i - 1;     //回到temp最后一个有意义的数字  
	while(i >= 0)  
	{  
	    *(*str)++ = temp[i];  
	    i--;  
	}
}

void 
struct2json(struct http_request_kinfo *httprequest, char *str)
{
    u_char *p;
    u_int num = 0;
    int urilen = 0, hostlen = 0, referlen = 0, ualen = 0, cookieslen = 0;

    urilen = httprequest->uri_end - httprequest->uri_start ;
    hostlen = httprequest->host_end - httprequest->host_start;
    referlen = httprequest->referer_end - httprequest->referer_start;
    ualen = httprequest->ua_end - httprequest->ua_start;
    cookieslen = httprequest->cookies_end - httprequest->cookies_start;

    if (urilen > 0)
    {
        *str++ = '{';
	*str++ = '\"';
        *str++ = 'U';
	*str++ = 'r';
	*str++ = 'l';
	*str++ = '\"';
	*str++ = ':';
	*str++ = '\"';
        
	if(hostlen > 0){
	    *str++ = 'h';
	    *str++ = 't';
	    *str++ = 't';
	    *str++ = 'p';
	    *str++ = ':';
	    *str++ = '/';
	    *str++ = '/';

	    for(p = httprequest->host_start ; p <= httprequest->host_end; p++,str++)
	    {
	        *str = *p;
	    }
	}    

	for (p = httprequest->uri_start; p <= httprequest->uri_end; p++, str++)
	{
	    if(*p == 34)
	    {
	        *str = '\"';
	    }
	    *str = *p;
	}

	*str++ = '\"';
    }
    else{
        return;
    }	

    if(ualen > 0)
    {
        *str++ = ',';
	*str++ = '\"';
	*str++ = 'U';
	*str++ = 's';
	*str++ = 'e';
	*str++ = 'r';
	*str++ = '-';
	*str++ = 'A';
	*str++ = 'g';
	*str++ = 'e';
	*str++ = 'n';
	*str++ = 't';
	*str++ = '\"';
	*str++ = ':';
	*str++ = '\"';
     
	for(p = httprequest->ua_start ; p <= httprequest->ua_end; p++,str++)
	{
	    if(*p == 34)
	    {
	        *str = '\"';
	    }
	    *str = *p;
	}

	*str++ = '\"';
    }	

    if(hostlen > 0)
    {
        *str++ = ',';
	*str++ = '\"';
	*str++ = 'H';
	*str++ = 'o';
	*str++ = 's';
	*str++ = 't';
	*str++ = '\"';
	*str++ = ':';
	*str++ = '\"';
     
	for(p = httprequest->host_start ; p <= httprequest->host_end; p++,str++)
	{
	    *str = *p;
	}

	*str++ = '\"';
    }	

    if(referlen > 0)
    {
        *str++ = ',';
	*str++ = '\"';
	*str++ = 'R';
	*str++ = 'e';
	*str++ = 'f';
	*str++ = 'e';
	*str++ = 'r';
	*str++ = 'e';
	*str++ = 'r';
	*str++ = '\"';
	*str++ = ':';
	*str++ = '\"';
     
	for(p = httprequest->referer_start ; p <= httprequest->referer_end; p++,str++)
	{
	    if(*p == 34)
	    {
	        *str = '\"';
	    }
	    *str = *p;
	}

	*str++ = '\"';
    }
    
    if(cookieslen > 0)
    {
        *str++ = ',';
	*str++ = '\"';
	*str++ = 'C';
	*str++ = 'o';
	*str++ = 'o';
	*str++ = 'k';
	*str++ = 'i';
	*str++ = 'e';
	*str++ = '\"';
	*str++ = ':';
	*str++ = '\"';
     
	for(p = httprequest->cookies_start ; p <= httprequest->cookies_end; p++,str++)
	{
	    if(*p == 34)
	    {
	        *str++ = '\\';
		*str = '\"';
	    }
	    *str = *p;
	}

	*str++ = '\"';
    }

    /* srcip */
    {
        *str++ = ',';
	*str++ = '\"';
	*str++ = 'S';
	*str++ = 'r';
	*str++ = 'c';
	*str++ = 'I';
	*str++ = 'P';
	*str++ = '\"';
	*str++ = ':';
	*str++ = '\"';
     
        num = httprequest->sip;
        int2str(num, &str);

	*str++ = '\"';
    }

    {
        *str++ = ',';
	*str++ = '\"';
	*str++ = 'D';
	*str++ = 's';
	*str++ = 't';
	*str++ = 'I';
	*str++ = 'P';
	*str++ = '\"';
	*str++ = ':';
	*str++ = '\"';
     
        num = httprequest->dip;
        int2str(num, &str);

	*str++ = '\"';
    }
    
    {
        *str++ = ',';
	*str++ = '\"';
	*str++ = 'T';
	*str++ = 'i';
	*str++ = 'm';
	*str++ = 'e';
	*str++ = 's';
	*str++ = 't';
	*str++ = 'a';
	*str++ = 'm';
	*str++ = 'p';
	*str++ = '\"';
	*str++ = ':';
	*str++ = '\"';
     
        num =(u_int)( httprequest->sec);
        int2str(num, &str);

	*str++ = '.';

	num =(u_int)(httprequest->usec);
        int2str(num, &str);

	*str++ = '\"';
    }
    *str++ = '}';
    *str = '\0';
}

int
http_parse_request(struct http_request_kinfo *httprequest)
{
    u_char *payload;
    u_char  ch, *p, *t, *m = NULL;
    int len, i = 0;

    payload = httprequest->content;
    len = httprequest->len * 10;

    char str[len];

    enum {
        sw_start = 0,
        sw_method,
        sw_spaces_before_uri,
        sw_uri,
        sw_http_09,
        sw_spaces_after_digit,
	sw_head_start,
	sw_name,
	sw_space_before_value,
	sw_value,
	sw_space_after_value,
	sw_ignore_line,
        sw_almost_done
    } state;

    state = sw_start;

    p = payload;

    for (i = 0; i < len; i++,p++) {
        ch = *p;

        switch (state) {

        /* HTTP methods: GET */
        case sw_start:
            
	    m = p;

            if (ch == CR || ch == LF) 
	    {
                break;
            }

            if (ch < 'A' || ch > 'Z') 
	    {
                return 1;
            }

            state = sw_method;
            break;

        case sw_method:
            
	    if (ch == ' ') 
	    {
                if (((p - m) == 3) && str3_cmp(m, 'G', 'E', 'T', ' ')) 
		{
		    state = sw_spaces_before_uri;
		    break;
                }
                else
		{
		    return 1;
		}
            }

            if (ch < 'A' || ch > 'Z') 
	    {
                return 1;
            }
	    
            break;
	case sw_spaces_before_uri:
	    
	    if (ch == '/'){
	        m = p;
		httprequest->uri_start = p;
		state = sw_uri;
		break;
	    }

	    switch (ch) {
	    case ' ':
	        break;
	    default:
	        return 1;
	    }
	    break;

        case sw_uri:

	    switch(ch){
            case ' ':

	        httprequest->uri_end = p - 1;
		t = httprequest->uri_end ;
		m = (t - m > 10)?(t - 10):m;
		for(; t > m; t--)
		{
		    if(*t == '.')
		    {
   //                      if(SuffixSearch(t + 1) != -1)
			// {
		 //            return 1;
		 //        }
			break;
		    }    
		}
		    
		state = sw_http_09;
		break;
	    case '?':
		t = p - 1;
		m = (t - m > 10)?(t - 10):m;
		for(; t > m; t--)
		{
		    if(*t == '.')
		    {
   //                      if(SuffixSearch(t + 1) != -1)
			// {
		 //            return 1;
		 //        }
			break;
		    }    
		}
	        break;
	    case CR:
	        return 1;
	    case LF:
	        return 1;
	    case '\0':
	        return 1;
	    default:
	        break;
	    }
	    break;

        case sw_http_09:

	    switch (ch) {
	    case ' ':
	        break;
	    case CR:
	        return 1;
	    case LF:
	        return 1;
	    case 'H':
	        state = sw_spaces_after_digit;
		break;
	    default: //space in uri;
	        state = sw_uri;
		break;
	    }
	    break;
	
	case sw_spaces_after_digit:
	    switch (ch) {
	    case ' ':
	        break;
	    case CR:
	        break;
	    case LF:
	        state = sw_head_start;
		break;
	    }
	    break;

	case sw_head_start:
	    switch (ch) {
	    case ' ':
	        break;
	    case CR:
	        state = sw_almost_done;		
		break;
            case LF:
		goto request_done;
	    default:
	        
		if (ch < 'A' || ch > 'Z') 
		{
		    return 1;
		}

		if(ch == '\0')
		{
		    return 1;
		}

		m = p;
		state = sw_name;

		break;
	    }
	    break;

        case sw_name:

	    if(ch == ' ' || ch == ':' ){
	       
	        switch(p - m){

	        case 4://Host
		    if(str4cmp(m, 'H', 'o', 's', 't')){
		        state = sw_space_before_value;
			httprequest->headerstate = HS_HOST;
		        break;
		    }
		    state = sw_space_after_value;
		    break;

	        case 6://Cookie
	            if(str6cmp(m, 'C', 'o', 'o', 'k', 'i', 'e')){
		        state = sw_space_before_value;
			httprequest->headerstate = HS_COOKIE;
		        break;
		    }
		    state = sw_space_after_value;
		    break;
	        case 7://Referer
	            if(str5cmp(m, 'R', 'e', 'f', 'e', 'r')){
		        state = sw_space_before_value;
			httprequest->headerstate = HS_REFERER;
		        break;
		    }
		    state = sw_space_after_value;
		    break;
	        case 10://User-Agent
	            if(str5cmp(m, 'U', 's', 'e', 'r', '-')){
		        state = sw_space_before_value;
			httprequest->headerstate = HS_USER_AGENT;
		        break;		       
		    }
		    state = sw_space_after_value;
		    break;
		default:
		    state = sw_space_after_value;
		    break;
	        }

	    }

	    break;

       case sw_space_before_value:
           
           if(ch == ':'){
	       break;
	   }

	   if(ch == ' '){
	       break;
	   }
	   
	   m = p;
	   state = sw_value;
	   break;

       case sw_value:
           switch (ch) {
	   case ' ':
	       //state = sw_space_after_value;
	       break;
	   case CR:

	       switch (httprequest->headerstate){
	       case HS_HOST:
                   httprequest->host_start = m;
		   httprequest->host_end = p - 1;
	       break;
	       case HS_USER_AGENT:
		   httprequest->ua_start = m;
		   httprequest->ua_end = p - 1;
	       break;	   
	       case HS_REFERER:
                   httprequest->referer_start = m;
		   httprequest->referer_end = p - 1;
	       break;
	       case HS_COOKIE:
                   httprequest->cookies_start = m;
		   httprequest->cookies_end = p - 1;
	       break;
	       default:
	           return 1;
	       }
	       break;
	   case LF:
	       
	       state = sw_head_start;
	       break;
	   case '\0':
	       return 1;
	   default: 
	       break;
           }

	   break;
           
       case sw_space_after_value:
           switch (ch) {
	   case ' ':
	       break;
	   case CR:
	       break;
	   case LF:
	       state = sw_head_start;
	       break;
	   case '\0':
	       return 1;
	   default:
	       break;//return 1;
	   }
	   break;
       case sw_almost_done:
           switch (ch) {
	   case LF:
	       goto request_done;
	   case CR:
	       break;
	   default:
	       return 1;
	   }
	   break;
	default:
	    return 1;

        }
    }

request_done:

    /* json string assemble */
    struct2json(httprequest, str);

    fputs(str,ffp);
    fputs("\n",ffp);

    printf("%s\n",str);

    /* insert into zeromq */
    //sendmsgZmq(dcClient, str);

    return 0;
}


/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

    int i;
    int gap;
    const u_char *ch;

    /* offset */
    printf("%05d   ", offset);

    /* hex */
    ch = payload;
    for(i = 0; i < len; i++) {
	printf("%02x ", *ch);
	ch++;
	/* print extra space after 8th byte for visual aid */
	if (i == 7)
		printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
	printf(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16) {
	gap = 16 - len;
	for (i = 0; i < gap; i++) {
		printf("   ");
	}
    }
    printf("   ");

    /* ascii (if printable) */
    ch = payload;
    for(i = 0; i < len; i++) {
	if (isprint(*ch))
   	    printf("%c", *ch);
	else
	    printf(".");
	ch++;
    }

    printf("\n");

    return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

    int len_rem = len;
    int line_width = 16;			/* number of bytes per line */
    int line_len;
    int offset = 0;					/* zero-based offset counter */
    const u_char *ch = payload;

    if (len <= 0)
	return;

    /* data fits on one line */
    if (len <= line_width) {
	print_hex_ascii_line(ch, len, offset);
	return;
    }

    /* data spans multiple lines */
    for ( ;; ) {
	/* compute current line length */
	line_len = line_width % len_rem;
	/* print line */
	print_hex_ascii_line(ch, line_len, offset);
	/* compute total remaining */
	len_rem = len_rem - line_len;
	/* shift pointer to remaining bytes to print */
	ch = ch + line_len;
	/* add offset */
	offset = offset + line_width;
	/* check if we have line width chars or less */
	if (len_rem <= line_width) {
    	    /* print last line and get out */
     	    print_hex_ascii_line(ch, len_rem, offset);
	    break;
	}
    }

return;
}

/*
 * dissect/print packet
 */
void
got_packet(const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IPv4 header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const u_char *payload;                    /* Packet payload */
	struct http_request_kinfo http =              \
	                {
	                    .host_start = NULL, 
	                    .host_end = NULL, 
	                    .ua_start = NULL,
	                    .ua_end = NULL,
	                    .referer_start = NULL,
	                    .referer_end = NULL,
	                    .uri_start = NULL,
	                    .uri_end = NULL,
	                    .cookies_start = NULL,
	                    .cookies_end = NULL,
			    .content = NULL,
			    .len = 0
	                };        /* http request */

	int size_ip;
	int size_tcp;
	int size_payload;

	//printf("\nPacket number %d:\n", count);
	count++;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	//printf("       From: %s\n", inet_ntoa(ip->ip_src));
	//printf("         To: %s\n", inet_ntoa(ip->ip_dst));
	
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			//printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
                case IPPROTO_GRE:
                        printf("   Protocol: GRE\n");
                        return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}
	
	/*
	 *  OK, this packet is TCP.
	 */
	

	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
	//printf("   Src port: %d\n", ntohs(tcp->th_sport));
	//printf("   Dst port: %d\n", ntohs(tcp->th_dport));

	if (ntohs(tcp->th_dport) == 80 ){

	    /* compute tcp payload (segment) size */
	    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	    /*
	     * Print payload data; it might be binary, so don't just
	     * treat it as a string.
	     */
	    if (size_payload > 0) {

                /* get timestamp from cap packet's header */
	        http.sec = header->ts.tv_sec;
                http.usec = header->ts.tv_usec;

		/* get ip address from ip header */
	        http.sip = ip->ip_src.s_addr;
	        http.dip = ip->ip_dst.s_addr;
	
                /* define/compute tcp payload (segment) offset */
	        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	        http.content = payload;
                http.len = size_payload;

		http_parse_request(&http);
		//print_payload(payload, size_payload);
	    }
	}


return;
}

int main(int argc, char **argv)
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "tcp dst port 80";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = -1;			/* number of packets to capture */
        ffp = fopen("cap1.txt","a");

	// SuffixHashinit();

//	/* check for capture device name on command-line */
//	if (argc == 2) {
//		dev = argv[1];
//	}
//	else if (argc > 2) {
//		fprintf(stderr, "error: unrecognized command-line options\n\n");
//		exit(EXIT_FAILURE);
//	}
//	else {
//		/* find a capture device if not specified on command-line */
//		dev = pcap_lookupdev(errbuf);
//		if (dev == NULL) {
//			fprintf(stderr, "Couldn't find default device: %s\n",
//			    errbuf);
//			exit(EXIT_FAILURE);
//		}
//	}
//	
//	/* get network number and mask associated with capture device */
//	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
//		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
//		    dev, errbuf);
//		net = 0;
//		mask = 0;
//	}
//
//	/* print capture info */
//	printf("Device: %s\n", dev);
//	printf("Number of packets: %d\n", num_packets);
//	printf("Filter expression: %s\n", filter_exp);
//
//	/* open capture device */
//	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
//	if (handle == NULL) {
//		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
//		exit(EXIT_FAILURE);
//	}
//
//	/* make sure we're capturing on an Ethernet device [2] */
//	if (pcap_datalink(handle) != DLT_EN10MB) {
//		fprintf(stderr, "%s is not an Ethernet\n", dev);
//		exit(EXIT_FAILURE);
//	}
//
//	/* compile the filter expression */
//	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
//		fprintf(stderr, "Couldn't parse filter %s: %s\n",
//		    filter_exp, pcap_geterr(handle));
//		exit(EXIT_FAILURE);
//	}
//
//	/* apply the compiled filter */
//	if (pcap_setfilter(handle, &fp) == -1) {
//		fprintf(stderr, "Couldn't install filter %s: %s\n",
//		    filter_exp, pcap_geterr(handle));
//		exit(EXIT_FAILURE);
//	}

	if (argc < 2) {
		exit(0);
	}

    char * filename;
    char * pCardName;
	
	if(strcmp(argv[1], "list")==0)
	{
		pcap_if_t* alldevs;
       	pcap_if_t* d;
       	pcap_findalldevs(&alldevs,errbuf);       // 获得网络设备指针
       	for(d=alldevs;d;d=d->next)               // 枚举网卡然后添加到ComboBox中
       	{
		 	printf("%s\n", d->name);      // d->name就是我们需要的网卡名字字符串，按照你// 自己的需要保存到你的相应变量中去
       	}
		pcap_freealldevs(alldevs);               // 释放alldev资源
		exit(0);
	}
	else if((strcmp(argv[1], "cap")==0) && (argc==3))
	{
		pCardName = argv[2];
	}
	else
	{
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		exit(-1);
	}
        // dcClient = initZmq("192.168.1.153", "5000");
        // if (!dcClient) {
        //     printf ("error in zmq_socket: %s\n", zmq_strerror (errno));
        //     return 1;
        // }
	handle = pcap_open_live(pCardName,65535,1,1000,errbuf);
  //       handle = pcap_open_offline(filename  , errbuf);
        if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
		}
	/* now we can set our callback function */
        struct pcap_pkthdr *pktHeader;
	int status;
	u_char *pktData;
	do{

	    status = pcap_next_ex(handle, &pktHeader, &pktData);
	    if(status == 1)
	    {
	    	printf("%s\n", "get a packet\n");
                got_packet(pktHeader,pktData);
	    }
	    if(status == 0)
	    {
	        sleep(100);
		continue;
	    }
	    else if(status == -2)
	    {
	        break;
	    }
	    //else
	    //{
	    //    break;
	    //}	
	    
	}while(1);    
	//pcap_loop(handle, num_packets, got_packet, NULL);

	/* cleanup */
	//pcap_freecode(&fp);
	pcap_close(handle);
        fclose(ffp);
	printf("\nCapture complete.\n");

return 0;
}

