/*
  grammar parsing for Cisco extended access lists

  Vladimir Kotal <vlada@devnull.cz>, 2004-2005

 */

%{
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>

#include "config.h"
#include "misc.h"

#define SET_PROTO(x)	proto = x; state = PROTO_STATE;

#define SET_TCPFLAG(x) 	if (tcp_flags & (x)) { \
		          yyerror("multiple TCP flags specified or wrong flags combination"); \
			  return(1); \
		       	} else { \
			  debug(DEBUG4, "SET_TCPFLAG", "flag set"); \
		          tcp_flags |= (x); \
	  		  state = PROTO_QUALIF_STATE; \
		       	}

#define SET_OQUAL(x)    { \
  			   int i; int found; int lastqual; \
  			   debug(DEBUG4, "SET_OQUAL", "check qual %d\n", x);  \
  			   for (i = 0; i < sizeof(qual_ids)/sizeof(int); i++) {  \
			     if (qual_ids[i] == 0) \
			       lastqual = i; \
    			     else if (qual_ids[i] == (x)) {  \
    			       found = 1; ;  \
    			       yyerror("multiple qualifiers of the same type");  \
    			       return(1);  \
			     } \
  			   } \
    			   qual_ids[lastqual] = (x);  \
    			   debug(DEBUG4, "SET_OQUAL", "qual %d %d\n", lastqual, x);  \
    			   state = PROTO_QUALIF_STATE;  \
			 }


int yyerror(char *fmt, ...);
extern int yylex(void);
extern int yyextparse(void);

int errors = 0;

int proto = -1;		/* protocol number; for checking port consistency */
int state;		/* state of parser (for err codes) */
int icmp_type_num;	/* number of specified ICMP type */
u_char tcp_flags;	/* TCP flags bitmask */
u_int qual_ids[20];	/* bitmask for other qualifiers */

/* XXX move this to header file */
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80

extern int lex_line;	/* last line read from acl file */
int acl_line;		/* line of last yy-parsed acl entry */

int rset_type = 0;	/* ruleset type */

%}

/* terminals */
%token  SLASH

%token  NUMBER LOWER_STR
%token  ACL PERMIT DENY REMARK REMARK_STR
%token  ICMP IP TCP UDP EQ NEQ GT LT RANGE ANY HOST

%token  IPV6

%token  DYNAMIC TIMEOUT

%token  ESTABL SYN ACK FIN PSH URG RST

%token  LOG LOG_INPUT LOG_UPDATE THRESHOLD
%token  IPV4ADDR IPV6ADDR 


%token  AH EIGRP ESP GRE IGMP IGRP IPINIP NOS OSPF 
%token  PRECEDENCE PREC_CRITICAL PREC_FLASH PREC_FLASH_OVERR PREC_IMMED
%token  PREC_INET PREC_NET PREC_PRIO PREC_ROUTINE

%token  TOS TOS_MAX_REL TOS_MAX_THRPUT TOS_MIN_DELAY TOS_MIN_MONET_COST
%token  TOS_NORMAL

%token  ADM_PROHIB ALT_ADDR CONV_ERR DOD_HOST_PROHIB DOD_NET_PROHIB ECHO 
%token  ECHO_REPLY GEN_PARAM_PROB HOST_ISOL MOB_REDIR NET_REDIR NET_TOS_REDIR
%token  NET_UNREACH NET_UNKN NO_ROOM_OPT OPT_MISSING PKT_TOO_BIG PARAM_PROB 
%token  PORT_UNREACH PREC_UNREACH PROT_UNREACH HOST_PREC_UNREACH HOST_REDIR 
%token  HOST_TOS_REDIR HOST_UNKN HOST_UNREACH INFO_REPLY INFO_REQ MASK_REPLY
%token  MASK_REQ REASS_TIMEOUT REDIR ROUTER_ADV ROUTER_SOL SRC_QUENCH 
%token  SRC_ROUTE_FAIL TIME_EXC TIME_REPLY TIME_REQ TRACERT TTL_EXC UNREACH

%token  DSCP FRAGMENTS TIME_RANGE

%token  BEYOND_SCOPE DEST_UNREACH ECHO_REQUEST FLOW_LABEL HEADER
%token  HOP_LIMIT MLD_QUERY MLD_REDUCTION MLD_REPORT ND_NA ND_NS
%token  NEXT_HEADER NO_ADMIN NO_ROUTE PKT_TOO_BIG PARAM_OPTION
%token  PARAM_PROB PORT_UNREACH REASS_TIMEOUT RENUM_CMD RENUM_RES
%token  RENUM_SEQ_NR ROUTER_ADV ROUTER_RENUM ROUTER_SOL ROUTING
%token  SEQUENCE TIME_EXCEED UNDET_TRAN

%token  AHP PCP SCTP

%token  REFLECT

%token  AF11 AF12 AF13 AF21 AF22 AF23 AF31 AF32 AF33 AF41 AF42 AF43 CS1
%token  CS2 CS3 CS4 CS5 CS6 CS7 DEFAULT EF

%token  <string_n> BGP CHARGEN CMD DAYTIME DISCARD DOMAIN ECHO EXEC FINGER FTP
%token  <string_n> FTP_DATA GOPHER HOSTNAME IDENT IRC KLOGIN KSHELL LOGIN LPD
%token  <string_n> NNTP PIM_AUTO_RP POP2 POP3 SMTP SUNRPC SYSLOG TACACS TALK 
%token  <string_n> TELNET TIME UUCP WHOIS WWW

%token  <string_n> BIFF BOOTPC BOOTPS DNSIX ISAKMP 
%token  <string_n> MOBILE_IP NAMESERVER NETBIOS_DGM NETBIOS_NS NETBIOS_SS 
%token  <string_n> NTP RIP SNMP SNMPTRAP TFTP WHO XDMCP

%token  <number_n> NUMBER

%token  <string_n> IPV4ADDR IPV6ADDR
%token  <string_n> REMARK_STR 
%token  <string_n> LOWER_STR 

%type   <number_n> number_extacl number_proto port_tcp port_udp 
%type   <number_n> icmp_numtype icmp_numcode

%type   <string_n> ipv4addr ipv6addr addr_spec
%type   <string_n> text_remark
%type   <string_n> port_udp_word port_tcp_word
%type   <portsp_n> port_spec_tcp port_spec_udp

/* stack for the parser */
%union {
        unsigned int number_n; /* all possible values in ACL syntax I know
			          of are positive */
        unsigned int timeout_n;
        char *string_n;
	portspec_t portsp_n;
}
%%

entries: /* empty */
	{
	}
	| entries extrule
	{
	}
	| entries ipv6acl
	{
	  /* allows multiple IPv6 ACLs in one file */
	}
	| entries ipv6log_spec
	{
	}
	;

ipv6acl: IPV6 acl text_remark ipv6acl_body
	{
	  if (rset_type & RSET_NONE)
	    rset_type |= RSET_IPV6;
	  else if (!(rset_type & RSET_IPV6)) {
	    yyerror("found rule with wrong type (should be in ipv6 format)");
	    return(1);
	  }

	  debug(DEBUG3, "ipv6acl", "ipv6 acl '%s'", $3);
	} 
	;

ipv6log_spec: IPV6 acl log_update_spec
	{
	}
	;

log_update_spec: LOG_UPDATE thresh_spec
	{
	  debug(DEBUG4, "ipv6acl_spec", "got log-update");
	}
	;

thresh_spec: THRESHOLD NUMBER
	{
	  if ($2 > INT_MAX) { /* XXX INT_MAX + 1 = 2147483648 = 2^32/2 */
	    yyerror("threshold value of out range <0-2147483647>");
	    return(1);
	  }
	  debug(DEBUG4, "ipv6acl_spec", "got threshold: %d", $2);
	}
	;

ipv6acl_body: /* empty */
	{
	}
	| ipv6acl_body ipv6rule
	{
	}
	| ipv6acl_body ipv6remark
	{
	}
	;

ipv6remark: REMARK text_remark
	{
	  debug(DEBUG4, "ipv6remark", "got remark: %s", $2);
	}
	;

ipv6rule: ipv6_default permit_deny ipv6rule_body
	{
	  debug(DEBUG3, "ipv6rule", "got ipv6rule");
	}
	;

ipv6_default: /* empty */
	{
	}
	| DEFAULT
	{
	}
	;

ipv6rule_body: ipv6rule_ipv6
	{
	}
	| ipv6rule_host
	{
	}
	| ipv6rule_prefix
	{
	}
	| ipv6rule_any
	{
	}
	| ipv6rule_noport
	{
	}
	| ipv6rule_tcp
	{
	}
	| ipv6rule_udp
	{
	}
	| ipv6rule_icmp
	{
	}
	| ipv6rule_sctp
	{
	}
	;

ipv6rule_ipv6: IPV6 ipv6_srcdst_noportspec ipv6_srcdst_noportspec ipv6rule_ipv6_qualif_list
	{
	}
	;

ipv6rule_icmp: icmp_proto ipv6_srcdst_noportspec ipv6_srcdst_noportspec ipv6rule_icmpspec ipv6rule_ipv6_qualif_list
	{
	}
	;

icmpv6_numqual: NUMBER NUMBER
	{
	  if (($1 > 255) || ($2 > 255)) {
	    yyerror("bad icmp type (%d) or code (%d) value (both should be <0-255>)", $1, $2);
	    return(1);
	  }
	}
	;

/* protocol qualifier for rules with protocol specified by number 
   or rules without port specification */
ipv6rule_ipv6_qualif_list: /* empty */
	{
	}
	| ipv6rule_ipv6_qualif_list ipv6rule_ipv6_qualif
	{
	}
	;

ipv6rule_ipv6_qualif: dscp_rule 
	{
	  SET_OQUAL(DSCP)
	}
	| flow_label_spec
	{
	  SET_OQUAL(FLOW_LABEL)
	}
	| logging
	{
	  SET_OQUAL(LOG|LOG_INPUT)
	}
	| reflect_spec
	{
	  SET_OQUAL(REFLECT)
	}
	| routing_spec
	{
	  SET_OQUAL(ROUTING)
	}
	| seq_spec
	{
	  SET_OQUAL(SEQUENCE)
	}
	| time_range_spec
	{
	  SET_OQUAL(TIME_RANGE)
	}
	;

seq_spec: SEQUENCE NUMBER
	{
	  if (($2 < 1) || ($2 > INT_MAX)) { /* XXX should be 4294967294 = INT_MAX * 2 */
	    yyerror("sequence number out of range <1-4294967294>");
	    return(1);
	  }
	}
	;

routing_spec: ROUTING
	{
	  /* XXX */
	}
	;

flow_label_spec: FLOW_LABEL NUMBER
	{
	  if (($2 > 1048575) || ($2 < 0)) {
	    yyerror("flow number out of range (0-1048575)");
	    return(1);
	  }
	}
	;

ipv6_srcdst_noportspec: ipv6prefix 
	{
	}
	| HOST ipv6addr
	{
	}
	| ANY
	{
	}
	;

ipv6_srcdst_tcpportspec: ipv6prefix port_spec_tcp 
	{
	}
	| HOST ipv6addr port_spec_tcp
	{
	}
	| ANY port_spec_tcp
	{
	}
	;

ipv6_srcdst_udpportspec: ipv6prefix port_spec_udp
	{
	}
	| HOST ipv6addr port_spec_udp
	{
	}
	| ANY port_spec_udp
	{
	}
	;

ipv6rule_host: HOST
	{
	  /* XXX not ready */
	}
	;

ipv6rule_prefix: ipv6prefix
	{
	  /* XXX not ready */
	}
	;

ipv6addr: IPV6ADDR
	{
	  debug(DEBUG3, "ipv6addr", "valid IPv6 addr: %s", $1);
	}
	;

ipv6prefix: ipv6addr SLASH NUMBER
	{
	  if ($3 > 128) {
	    yyerror("bad prefix len");
	    return(1);
	  }
	  debug(DEBUG3, "ipv6prefix", "got ipv6 prefix '%s/%d", $1, $3);
	}
	;

ipv6rule_any: ANY
	{
	  /* XXX */
	}
	;

ipv6rule_noport: ipv6_protocol_noports ipv6_srcdst_noportspec ipv6_srcdst_noportspec ipv6rule_ipv6_qualif_list
	{
	  /* XXX */
	}
	;

ipv6_protocol_noports: NUMBER 
	{
	  if (($1 < 0) || ($1 > 255)) {
	    yyerror("IPv6 protocol number must be from range <0-255>");
	    return(1);
	  }

	  SET_PROTO($1)
	}
	| ESP
	{
	  SET_PROTO(50)
	}
	| AHP
	{
	  SET_PROTO(51) /* AH = Authentication Header Protocol */
	}
	| PCP /* PCP = Payload Compression Protocol */
	{
	  SET_PROTO(108)
	}
	;

ipv6rule_tcp: tcp_proto ipv6_srcdst_tcpportspec ipv6_srcdst_tcpportspec tcp_flags_list other_tcp_ipv6_qualif
	{
	}
	;

other_tcp_ipv6_qualif: /* empty */
	{
	}
	| logging
	{
	 /* XXX */
	}
	;

ipv6rule_udp: udp_proto ipv6_srcdst_udpportspec ipv6_srcdst_udpportspec
	{
	  /* other qualifiers XXX */
	}
	;

ipv6rule_sctp: sctp_proto
	{
	  /* XXX */
	}
	;

sctp_proto: SCTP
	{
	  SET_PROTO(132);
	}
	;

reflect_spec: REFLECT text_remark
	{
	}
	;

ipv6rule_icmpspec: /* empty */
	{
	}
	| icmpv6_numqual
	{
	}
	| BEYOND_SCOPE
	{
	}
	| DEST_UNREACH
	{
	}
	| ECHO_REPLY
	{
	}
	| ECHO_REQUEST
	{
	}
	| HEADER
	{
	}
	| HOP_LIMIT
	{
	}
	| MLD_QUERY
	{
	}
	| MLD_REDUCTION
	{
	}
	| MLD_REPORT
	{
	}
	| ND_NA
	{
	}
	| ND_NS
	{
	}
	| NEXT_HEADER
	{
	}
	| NO_ADMIN
	{
	}
	| NO_ROUTE
	{
	}
	| PKT_TOO_BIG
	{
	}
	| PARAM_OPTION
	{
	}
	| PARAM_PROB
	{
	}
	| PORT_UNREACH
	{
	}
	| REASS_TIMEOUT
	{
	}
	| RENUM_CMD
	{
	}
	| RENUM_RES
	{
	}
	| RENUM_SEQ_NR
	{
	}
	| ROUTER_ADV
	{
	}
	| ROUTER_RENUM
	{
	}
	| ROUTER_SOL
	{
	}
	| TIME_EXCEED
	{
	}
	| UNREACH
	{
	}
	;

extrule_prefix: acl number_extacl dynamic_spec permit_deny 
	{
	  debug(DEBUG2, "access-list", "got access-list %d", $2);
	}
	;


/*
 *
 *  here begins IPv4 extended ACL syntax specification
 *
 */


/* IPv4 rule in Extended ACL format */
extrule: acl number_extacl REMARK text_remark
	{
	  if (rset_type & RSET_NONE)
	    rset_type |= RSET_EXTENDED;
	  else if (!(rset_type & RSET_EXTENDED)) {
	    yyerror("found rule with wrong type (should be in extended format)");
	    return(1);
	  }

	  debug(DEBUG3, "rule", "remark: %s", $4); 
	  state = -1;
	}
	| extrule_prefix tcp_rule 
	{
	}
	| extrule_prefix udp_rule
	{
	}
	| extrule_prefix icmp_rule
	{
	}
	| extrule_prefix noports_rule
	{
	}
	| extrule_prefix protbynum_rule
	{
	}
	;

tcp_rule: tcp_proto srcdst_portspec_tcp srcdst_portspec_tcp tcp_flags_list other_qualifier_list
	{
	  state = -1;
	}
	;

udp_rule: udp_proto srcdst_portspec_udp srcdst_portspec_udp other_qualifier_list 
	{
	  state = -1;
	}
	;

icmp_rule: icmp_proto srcdst_noportspec srcdst_noportspec icmp_qualifier other_qualifier_list
	{
	  state = -1;
	}
	;

noports_rule: protocol_noports srcdst_noportspec srcdst_noportspec other_qualifier_list
	{
	}
	;

/* 
 * rule with protocol specified numerically cannot have src/dst specified
 * along with port number 
 */
protbynum_rule: protocol_number srcdst_noportspec srcdst_noportspec other_qualifier_list
	{
	}
	;

dynamic_spec: /* empty */
	{
	  /* not-dynamic ACL entry */
	}
	| DYNAMIC REMARK_STR timeout_spec
	{
	  /* XXX maybe REMARK_STR is not what we want */
	}
	;

timeout_spec:
	{
	  /* empty timeout specification */
	}
	| TIMEOUT NUMBER
	{
	  if (($2 <= 0) || ($2 >= 9999)) {
	    yyerror("invalid timeout range (out of 1-9999)");
	    return(1);
	  }
	  debug(DEBUG3, "timeout_spec", "timeout = %d", $2);
	}
	;

text_remark: REMARK_STR
	{
	  if (strlen($1) > 100) {
	    yyerror("remark string longer than 100 characters");
	    return(1);
	  }
	
	  $$ = $1;
	}
	;

acl: ACL
	{
	  int i;

	  /* catch error on correct line if at least ACL is right */
	  state = ACL_KEYW_STATE;
	  acl_line = lex_line;

	  for (i = 0; i < sizeof(qual_ids)/sizeof(int); i++) 
	    qual_ids[i] = 0;
	  debug(DEBUG3, "acl", "qualifiers zeroed");
	}
	;

number_extacl: NUMBER
	{
	  debug(DEBUG2, "number_extacl", "got number: %d", $1);

	  /*
	    <100-199>         IP extended access list
	    <2000-2699>       IP extended access list (expanded range)
	   */
	  if (!((($1 >= 100) && ($1 <= 199)) || 
	  	(($1 >= 2000) && ($1 <= 2699)))) {
	    debug(ERROR, "access-list", "access-list number must be 100-199");
	    yyerror("access-list number on line %d must be 100-199 or 2000-2699 (expanded range)", lex_line);
	    return(1);    
	  }

	  state = ACL_NUM_STATE;
	  $$ = $1;
	}
	;

permit_deny: PERMIT
	{
	  state = PERMIT_DENY_STATE;
	  debug(DEBUG3, "permit_deny", "got permit");
	}
	| DENY
	{
	  state = PERMIT_DENY_STATE;
	  debug(DEBUG3, "permit_deny", "got deny");
	}
	;

protocol_noports: AH
	{
	  /* XXX only in IPsec-enabled IOSes ? */
	  SET_PROTO(51)
	}
 	| EIGRP
	{
	  SET_PROTO(88)
	}
	| ESP
	{
	  /* XXX only in IPsec-enabled IOSes ? */
	  SET_PROTO(50)
	}
	| GRE
	{
	  SET_PROTO(47)
	}
	| IGMP
	{
	  SET_PROTO(2)
	}
	| IGRP
	{
	  /* XXX SET_PROTO() */
	}
	| IP
	{
	  SET_PROTO(0)
	}
	| IPINIP
	{
	  SET_PROTO(94) /* is that right ? */
	}
	| NOS
	{
	  /* XXX SET_PROTO() */
	}
	| OSPF
	{
	  SET_PROTO(89)
	}
	;

protocol_number: number_proto
	{
	  SET_PROTO($1)
	}
	;

tcp_proto: TCP /* we need this rule to set proto variable before port
	          specification is evaluated.
	          similary for udp.
	        */
	{
	  SET_PROTO(6);
	  tcp_flags = 0; 
	  debug(DEBUG2, "protocol", "tcp");
	}
	;

udp_proto: UDP
	{
	  SET_PROTO(17)
	  debug(DEBUG2, "protocol", "udp");
	}
	;

icmp_proto: ICMP
	{
	  SET_PROTO(1);
	  debug(DEBUG2, "protocol", "icmp");
	}
	;

number_proto: NUMBER 
	{
	  debug(DEBUG2, "number", "got number: %d", $1);

	  if (($1 < 0) || ($1 > 255)) {
	    yyerror("bad IP protocol number (only range 0-255 is valid)");
	    return(1);
	  }

	  /* XXX check proto number again */
	  if (!getprotobynumber($1)) {
	    yyerror("wrong protocol number");
	    return(1);
	  }

	  $$ = $1;
	}
	;

srcdst_noportspec: HOST addr_spec 
	{
	  if (!valid_ipaddr(AF_INET, $2, NULL)) {
	    yyerror("invalid ip address: %s", $2);
	    return(1);
	  }
	}
	| ANY 
	{
	  debug(DEBUG3, "srcdst_spec", "got ANY");
	  if (state == SRC_SPEC_STATE)
	    state = DST_SPEC_STATE;
	  else
	    state = SRC_SPEC_STATE;
	}
	| ipv4addr ipv4addr 
	{
	  /* XXX check if ip addrs are valid */
	  if (!valid_ipaddr(AF_INET, $1, NULL)) {
	    yyerror("invalid ip address: %s", $1);
	    return(1);
	  }
	  if (!valid_ipaddr(AF_INET, $2, NULL)) {
	    yyerror("invalid ip address: %s", $2);
	    return(1);
	  }
	}
	;

srcdst_portspec_tcp: HOST addr_spec port_spec_tcp
	{
	  /* XXX check if ip addr is valid */
	  if (!valid_ipaddr(AF_INET,
	  	$2, $3.type == EQ_PORTSPEC ? $3.low : NULL)) {
	    yyerror("invalid ip address: %s", $2);
	    return(1);
	  }
	  /* XXX debug(DEBUG3, "srcdst_spec", "host %s %s"); */
	}
	| ANY port_spec_tcp
	{
	  debug(DEBUG3, "srcdst_spec", "got ANY");
	  if (state == SRC_SPEC_STATE)
	    state = DST_SPEC_STATE;
	  else
	    state = SRC_SPEC_STATE;
	}
	| addr_spec addr_spec port_spec_tcp
	{
#if 0
	  /* XXX check if ip addrs are valid */
	  if (!valid_ipaddr(AF_INET, $1, NULL)) {
	    yyerror("invalid ip address: %s", $1);
	    return(1);
	  }
	  if (!valid_ipaddr(AF_INET, $3, NULL)) {
	    yyerror("invalid ip address: %s", $3);
	    return(1);
	  }
#endif
	}
	;

srcdst_portspec_udp: HOST addr_spec port_spec_udp
	{
	  /* XXX check if ip addr is valid */
	  if (!valid_ipaddr(AF_INET,
	  	$2, $3.type == EQ_PORTSPEC ? $3.low : NULL)) {
	    yyerror("invalid ip address: %s", $2);
	    return(1);
	  }
	  /* XXX debug(DEBUG3, "srcdst_spec", "host %s %s"); */
	}
	| ANY port_spec_udp
	{
	  debug(DEBUG3, "srcdst_spec", "got ANY");
	  if (state == SRC_SPEC_STATE)
	    state = DST_SPEC_STATE;
	  else
	    state = SRC_SPEC_STATE;
	}
	| addr_spec addr_spec port_spec_udp
	{
	  /* XXX check if ip addrs are valid */
#if 0
	  if (!valid_ipaddr(AF_INET, $1, NULL)) {
	    yyerror("invalid ip address: %s", $1);
	    return(1);
	  }
	  if (!valid_ipaddr(AF_INET, $3, NULL)) {
	    yyerror("invalid ip address: %s", $3);
	    return(1);
	  }
#endif
	}
	;


/* addr_spec is for HOST only */
addr_spec: ipv4addr 
	{
	  debug(DEBUG3, "addr_spec", "ipv4addr = %s", $1);

	  $$ = $1;
	}
	| LOWER_STR
	{
	  struct addrinfo hints, /* XXX *res,*/ *res0;
	  int error;

	  debug(DEBUG3, "addr_spec", "hostname = %s", $1);

	  /* XXX check if it resolves into valid IP address 
	     XXX make it configurable
	  */
	  /* const char *cause = NULL; */

	  memset(&hints, 0, sizeof(hints));
          hints.ai_family = PF_UNSPEC;
	  hints.ai_socktype = SOCK_STREAM;

	  /* XXX check with port */
	  error = getaddrinfo($1, NULL, &hints, &res0);
	  if (error) {
	     yyerror("invalid hostname (%s)", gai_strerror(error));
	     return(1);
	  }
	  /* XXX write address of hostname
	  for (res = res0; res; res = res->ai_next) {
	  }
	  */
	  freeaddrinfo(res0);

	  $$ = $1;
	}
	;

ipv4addr: IPV4ADDR
	{
	  debug(DEBUG3, "ipv4addr", "valid IPv4 addr: %s", $1);

	  if (state == SRC_SPEC_STATE)
	    state = DST_SPEC_STATE;
	  else
	    state = SRC_SPEC_STATE;

	  $$ = $1;
	}
	;

port_spec_tcp:
	{
	  /* empty port spec */
	  debug(DEBUG2, "port_spec", "empty port spec");
	  $$.type = EMPTY_PORTSPEC;
	}
	| unary_portspec port_tcp
	{
	  debug(DEBUG2, "port_spec", "port %d with unary spec (eq/neq/gt/lt)", $2);
	  if (proto != 6) {
	    yyerror("TCP port specification does not match protocol (%d)",
	    proto);
	    return(1);
	  }
	  $$.type = EQ_PORTSPEC;
	  $$.low = $2;
	}
	| RANGE port_tcp port_tcp
	{
 	  if (proto != 6) {
	    yyerror("TCP port range specification does not match protocol (%d)", proto);
	    return(1);
	  }
	  PRANGE_CHECK($2,$3);
	  debug(DEBUG2, "port_spec", "port range %d %d", $2, $3);
	  $$.type = RANGE_PORTSPEC;
	}
	;

port_spec_udp:
	{
	  /* empty port spec */
	  debug(DEBUG2, "port_spec", "empty port spec");
	  $$.type = EMPTY_PORTSPEC;
	}
	| unary_portspec port_udp
	{
	  debug(DEBUG2, "port_spec", "port %d with unary spec (eq/neq/gt/lt)", $2);
	  if (proto != 17) {
	    yyerror("UDP port specification does not match protocol (%d)",
	    proto);
	    return(1);
	  }
	  $$.type = EQ_PORTSPEC;
	  $$.low = $2;
	}
	| RANGE port_udp port_udp
	{
 	  if (proto != 17) {
	    yyerror("UDP port range specification does not match protocol (%d)", 
	    proto);
	    return(1);
	  }
	  PRANGE_CHECK($2,$3);
	  debug(DEBUG2, "port_spec", "port range %d %d", $2, $3);
	  $$.type = RANGE_PORTSPEC;
	}
	;

unary_portspec: GT
	{
	  debug(DEBUG4, "unary_portspec", "gt");
	}
	| EQ 
	{
	  debug(DEBUG4, "unary_portspec", "eq");
	}
	| NEQ
	{
	  debug(DEBUG4, "unary_portspec", "neq");
	}
	| LT 
	{
	  debug(DEBUG4, "unary_portspec", "lt");
	}
	;

port_tcp_word: BGP 
	{
	  $$ = $1;
	}
	| CHARGEN 
	{
	  $$ = $1;
	}
	| CMD 
	{
	  $$ = $1;
	}
	| DAYTIME 
	{
	  $$ = $1;
	}
	| DISCARD 
	{
	  $$ = $1;
	}
	| DOMAIN 
	{
	  $$ = $1;
	}
	| ECHO 
	{
	  $$ = $1;
	}
	| EXEC 
	{
	  $$ = $1;
	}
	| FINGER 
	{
	  $$ = $1;
	}
	| FTP
	{
	  $$ = $1;
	}
	| FTP_DATA 
	{
	  $$ = $1;
	}
	| GOPHER 
	{
	  $$ = $1;
	}
	| HOSTNAME 
	{
	  $$ = $1;
	}
	| IDENT 
	{
	  $$ = $1;
	}
	| IRC 
	{
	  $$ = $1;
	}
	| KLOGIN 
	{
	  $$ = $1;
	}
	| KSHELL 
	{
	  $$ = $1;
	}
	| LOGIN 
	{
	  $$ = $1;
	}
	| LPD
	{
	  $$ = $1;
	}
	| NNTP 
	{
	  $$ = $1;
	}
	| PIM_AUTO_RP 
	{
	  $$ = $1;
	}
	| POP2 
	{
	  $$ = $1;
	}
	| POP3 
	{
	  $$ = $1;
	}
	| SMTP 
	{
	  $$ = $1;
	}
	| SUNRPC 
	{
	  $$ = $1;
	}
	| SYSLOG 
	{
	  $$ = $1;
	}
	| TACACS 
	{
	  $$ = $1;
	}
	| TALK 
	{
	  $$ = $1;
	}
	| TELNET
	{
	  $$ = $1;
	}
	| TIME 
	{
	  $$ = $1;
	}
	| UUCP 
	{
	  $$ = $1;
	}
	| WHOIS 
	{
	  $$ = $1;
	}
	| WWW
	{
	  $$ = $1;
	}
	;

port_tcp: NUMBER 
	{
	  /* XXX check port number validity */
  	  if (!valid_portnr($1)) {
	    yyerror("invalid port number: %d", $1);
	    return(1);
	  }
	  $$ = $1;
	}
	| port_tcp_word
	{
	  int portval = 0;
	
	  debug(DEBUG4, "port", "got TCP_PORT: %s", $1);

	  portval = check_servname($1);

	  $$ = portval;
	} 
	;


port_udp_word: BIFF 
	{
	  $$ = $1;
	}
	| BOOTPC 
	{
	  $$ = $1;
	}
	| BOOTPS 
	{
	  $$ = $1;
	}
	| DISCARD 
	{
	  $$ = $1;
	}
	| DNSIX 
	{
	  $$ = $1;
	}
	| DOMAIN 
	{
	  $$ = $1;
	}
	| ECHO 
	{
	  $$ = $1;
	}
	| ISAKMP 
	{
	  $$ = $1;
	}
	| MOBILE_IP
	{
	  $$ = $1;
	}
	| NAMESERVER 
	{
	  $$ = $1;
	}
	| NETBIOS_DGM  
	{
	  $$ = $1;
	}
	| NETBIOS_NS
	{
	  $$ = $1;
	}
	| NETBIOS_SS 
	{
	  $$ = $1;
	}
	| NTP 
	{
	  $$ = $1;
	}
	| PIM_AUTO_RP 
	{
	  $$ = $1;
	}
	| RIP 
	{
	  $$ = $1;
	}
	| SNMP
	{
	  $$ = $1;
	}
	| SNMPTRAP 
	{
	  $$ = $1;
	}
	| SUNRPC 
	{
	  $$ = $1;
	}
	| SYSLOG 
	{
	  $$ = $1;
	}
	| TACACS 
	{
	  $$ = $1;
	}
	| TALK 
	{
	  $$ = $1;
	}
	| TFTP 
	{
	  $$ = $1;
	}
	| TIME 
	{
	  $$ = $1;
	}
	| WHO 
	{
	  $$ = $1;
	}
	| XDMCP
	{
	  $$ = $1;
	}
	;

port_udp: NUMBER 
	{
	  /* XXX check port number validity */
  	  if (!valid_portnr($1)) {
	    yyerror("invalid port number: %d", $1);
	    return(1);
	  }
	  $$ = $1;
	}
	| port_udp_word
	{
	  int portval = 0;

 	  debug(DEBUG4, "port", "got UDP_PORT: %s", $1);

	  portval = check_servname($1);

	  $$ = portval;
	}
	;


/* XXX for the time beiing, use RAMARK_STR */
time_range_spec: TIME_RANGE REMARK_STR
	{
	}
	;

dscp_spec: NUMBER
	{
	  if (($1 < 0) || ($1 > 63)) {
	    yyerror("wrong number in dscp specification: %d", $1);
	    return(1);
	  }
	}
	| AF11
	{
	}
	| AF12
	{
	}
	| AF13
	{
	}
	| AF21
	{
	}
	| AF22
	{
	}
	| AF23
	{
	}
	| AF31
	{
	}
	| AF32
	{
	}
	| AF33
	{
	}
	| AF41
	{
	}
	| AF42
	{
	}
	| AF43
	{
	}
	| CS1
	{
	}
	| CS2
	{
	}
	| CS3
	{
	}
	| CS4
	{
	}
	| CS5
	{
	}
	| CS6
	{
	}
	| CS7
	{
	}
	| DEFAULT
	{
	}
	| EF
	{
	}
	;

dscp_rule: DSCP dscp_spec
	{
	}
	;

other_qualifier_list: /* empty */
	{
	}
	| other_qualifier_list other_qualifier
	{
	}
	;

other_qualifier: dscp_rule /* Differentiated services codepoint value */
	{
	  SET_OQUAL(DSCP)
	}
	| FRAGMENTS
	{
	  SET_OQUAL(FRAGMENTS)
	}
	| logging
	{
	  SET_OQUAL(LOG|LOG_INPUT)
	}
	| tos_qualifier
	{
	  SET_OQUAL(TOS)
	}
	| precedence_qualifier
	{
	  SET_OQUAL(PRECEDENCE)
	}
	| time_range_spec
	{
	  SET_OQUAL(TIME_RANGE)
	}
	;

/* XXX need to have format <icmp_type> [icmp_code] ??? */
icmp_qualifier: /* empty */
	{
	}
	| ADM_PROHIB 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| ALT_ADDR    
	{
	  state = PROTO_QUALIF_STATE;
	}
	| CONV_ERR 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| DOD_HOST_PROHIB  
	{
	  state = PROTO_QUALIF_STATE;
	}
	| DOD_NET_PROHIB  
	{
	  state = PROTO_QUALIF_STATE;
	}
	| ECHO 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| ECHO_REPLY 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| GEN_PARAM_PROB 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| HOST_ISOL 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| MOB_REDIR 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| NET_REDIR 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| NET_TOS_REDIR
	{
	  state = PROTO_QUALIF_STATE;
	}
	| NET_UNREACH 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| NET_UNKN 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| NO_ROOM_OPT 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| OPT_MISSING 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| PKT_TOO_BIG 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| PARAM_PROB 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| PORT_UNREACH 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| PREC_UNREACH 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| PROT_UNREACH 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| HOST_PREC_UNREACH 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| HOST_REDIR 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| HOST_TOS_REDIR 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| HOST_UNKN 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| HOST_UNREACH 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| INFO_REPLY 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| INFO_REQ 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| MASK_REPLY
	{
	  state = PROTO_QUALIF_STATE;
	}
	| MASK_REQ 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| REASS_TIMEOUT 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| REDIR 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| ROUTER_ADV 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| ROUTER_SOL 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| SRC_QUENCH 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| SRC_ROUTE_FAIL 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| TIME_EXC 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| TIME_REPLY 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| TIME_REQ 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| TRACERT 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| TTL_EXC 
	{
	  state = PROTO_QUALIF_STATE;
	}
	| UNREACH
	{
	  state = PROTO_QUALIF_STATE;
	}
	| icmp_numqual
	{
	  state = PROTO_QUALIF_STATE;
	}
	;

icmp_numqual: icmp_numtype
	{
	}
	| icmp_numtype icmp_numcode
	{
	  debug(DEBUG4, "icmp_numqual", "icmp_numtype = %d", $1);
	  switch($1) {
	    case ICMP_UNREACH:
	    	if (($2 < ICMP_UNREACH_NET) 
			|| ($2 > 15)) { /* ICMP_UNREACH_PRECEDENCE_CUTOFF */
		  yyerror("invalid icmp code for this type (%d): %d", 
		    icmp_type_num, $2);
		  return(1);
		}
	    	break;
	    case ICMP_REDIRECT:
	    	if (($2 < 0 /* ICMP_REDIRECT_NET */) 
			|| ($2 > 3 /* ICMP_REDIRECT_TOSHOST */ )) {
  		  yyerror("invalid icmp code for this type (%d): %d", 
		    icmp_type_num, $2);
		  return(1);
		}
	    	break;
	    case ICMP_TIMXCEED:
		if (($2 != ICMP_TIMXCEED_INTRANS) && \
			($2 != ICMP_TIMXCEED_REASS)) {
  		  yyerror("invalid icmp code for this type (%d): %d", 
		    icmp_type_num, $2);
		  return(1);
		}
	    	break;
	    case ICMP_PARAMPROB:
		if (($2 < 0 /* ICMP_PARAMPROB_ERRATPTR */) || \
			($2 > 2 /* ICMP_PARAMPROB_LENGTH */)) {
  		  yyerror("invalid icmp code for this type (%d): %d", 
		    icmp_type_num, $2);
		  return(1);
		}
	    	break;
	    case ICMP_ECHO:
		if ($2 != 0) {
  		  yyerror("invalid icmp code for this type (%d): %d", 
		    icmp_type_num, $2);
		  return(1);
		}
		break;
	    default:
	    	yyerror("invalid icmp code %d for this type (%d) possible",
			$2, $1);
		return(1);
	  }

	}
	;

icmp_numtype: NUMBER
	{
	  if (($1 < ICMP_ECHOREPLY) || ($1 > ICMP_MAXTYPE)) {
	    yyerror("invalid icmp type (out of range): %d", $1);
	    return(1);
	  }
	  if (($1 == 2) || ($1 == 1) || ($1 == 6) || ($1 == 7)) {
	    yyerror("invalid icmp type (%d)", $1);
	    return(1);
	  }
	  $$ = $1;
	}
	;

icmp_numcode: NUMBER
	{
	  $$ = $1;
	}
	;

tcp_flags_list: /* empty */
	{
	}
	| tcp_flags_list tcp_flag
	{
	}
	;

/* ACK = ESTABL */
ack_flag: ESTABL
	{
	  SET_TCPFLAG(TH_ACK|TH_RST)
	}
	| ACK 
	{
	  SET_TCPFLAG(TH_ACK);
	}
	;

/* XXX TODO: allow multiple tcp flags in one rule:
   e.g. permit 111 tcp any any fin ack syn 
*/
/* no need to check proto number, tcp_flags is only valid in
   tcp_proto state context */
tcp_flag: ack_flag
	{
	}
	| SYN
	{
	  SET_TCPFLAG(TH_SYN);
	}
	| FIN
	{
	  SET_TCPFLAG(TH_FIN)
	}
	| PSH
	{
	  SET_TCPFLAG(TH_PUSH)
	}
	| URG
	{
	  SET_TCPFLAG(TH_URG)
	}
	| RST
	{
	  SET_TCPFLAG(TH_RST)
	}
	;

tos_qualifier: TOS tos_string
	{
	}
	| TOS NUMBER
	{
	  if (($2 < 0) || ($2 > 15)) {
	    yyerror("invalid tos number %d (0-15 is valid)", $2);
	    return(1);
	  }
	}
	;

tos_string: TOS_MAX_REL
	{
	}
	| TOS_MAX_THRPUT
	{
	}
	| TOS_MIN_DELAY
	{
	}
	| TOS_MIN_MONET_COST
	{
	}
	| TOS_NORMAL
	{
	}
	;

precedence_qualifier: PRECEDENCE precedence_string
	{
	}
	| PRECEDENCE NUMBER
	{
	  if (($2 < 0) || ($2 > 7)) {
	    yyerror("invalid preference number (0-7 is valid)");
	    return(1);
	  }
	}
	;

precedence_string: PREC_CRITICAL
	{
	}
	| PREC_FLASH
	{
	}
	| PREC_FLASH_OVERR
	{
	}
	| PREC_IMMED
	{
	}
	| PREC_INET
	{
	}
	| PREC_NET
	{
	}
	| PREC_PRIO
	{
	}
	| PREC_ROUTINE
	{
	}
	;

logging: LOG_INPUT
	{
	  state = LOGGING_STATE;
	}
	| LOG
	{
	  /* XXX debug(); */
	  state = LOGGING_STATE;
	}
	;

%%

extern FILE *yyin;
extern FILE *yyout;



/* 
 * call yyparse() function which will read config file
 * and fill Entrylist struct and ThisVars struct
 *
 * return NULL on failure, valid pointer to entrylist on success
 */
#if 0
entrylist_t *load_config(char *filename, vars_t **vars) {
#else
int load_config(char *filename) {
#endif
	// entry_t *e;

        errors = 0;

	rset_type |= RSET_NONE;

        if (!(yyin = fopen(filename, "r"))) {
          debug(ERROR, "load_config", "Unable to open \"%s\": %s",
            filename, strerror(errno));
          return((int)NULL);
        }
	if (!(yyout = fopen("/dev/null", "w+"))){
          debug(ERROR, "load_config", "yyout failed");
          return((int)NULL);
        }

	setservent(NULL);
        if (yyextparse()) {
          debug(ERROR, "load_config", "Parse error in \"%s\"", filename);
          return((int)NULL);
        }
	endservent();

        fclose(yyin);
        fclose(yyout);

	return(1);
}
