/*
  Lexical analysis for LALR parser for Cisco ACL checker

  parses config file into tokens

  Vladimir Kotal, 2004
 */

%{

#include <stdio.h>
#include <string.h>

#include "config.h"

#include "misc.h"
#include "extacl.h"

#ifdef __FreeBSD__
#define YY_NO_UNPUT
#endif

int yyexterror(char *fmt, ...);

char *mystring;
char errstr[255];
int lex_line = 1;

%}

%option noyywrap

num                     [0-9]
white                   [ \t]

%% /* rules */
{white}*        { ; }
{num}*          {
                  yylval.number_n = atoi(yytext);
                  return NUMBER;
                }

"/"		{ return SLASH; }
"ipv6"		{ return IPV6; }

"access-list"   { return ACL; }
"permit"	{ return PERMIT; }
"deny"		{ return DENY; }
"remark"	{ return REMARK; }

"dynamic"	{ return DYNAMIC; }
"timeout"	{ return TIMEOUT; }

"icmp"		{ return ICMP; }
"ip"		{ return IP; }
"tcp"		{ return TCP; }
"udp"		{ return UDP; }
"eq"		{ return EQ; }
"neq"		{ return NEQ; }
"gt"		{ return GT; }
"lt"		{ return LT; }
"range"		{ return RANGE; }
"any"		{ return ANY; }
"host"		{ return HOST; }

"established"	{ return ESTABL; }
"syn"		{ return SYN; }
"ack"		{ return ACK; }
"fin"		{ return FIN; }
"psh"		{ return PSH; }
"urg"		{ return URG; }
"rst"		{ return RST; }

"ah"		{ return AH; }
"eigrp"		{ return EIGRP; }
"esp"		{ return ESP; }
"gre"		{ return GRE; }
"igmp"		{ return IGMP; }
"igrp"		{ return IGRP; }
"ip"		{ return IP; }
"ipinip"	{ return IPINIP; }
"nos"		{ return NOS; }
"ospf"		{ return OSPF; }

"dscp"		{ return DSCP; }
"fragments"	{ return FRAGMENTS; }

"log-input"	{ return LOG_INPUT; }
"log-update"	{ return LOG_UPDATE; }
"log"		{ return LOG; }
"threshold"	{ return THRESHOLD; }

"precedence"	{ return PRECEDENCE; }
"time-range"	{ return TIME_RANGE; }
"tos"		{ return TOS; }

"administratively-prohibited"	{ return ADM_PROHIB; }
"alternate-address"		{ return ALT_ADDR; }
"conversion-error"		{ return CONV_ERR; }
"dod-host-prohibited"		{ return DOD_HOST_PROHIB; }
"dod-net-prohibited"		{ return DOD_NET_PROHIB; }
"echo"				{ return ECHO; }
"echo-reply"			{ return ECHO_REPLY; }
"general-parameter-problem"	{ return GEN_PARAM_PROB; }
"host-isolated"			{ return HOST_ISOL; }
"mobile-redirect"		{ return MOB_REDIR; }
"net-redirect"			{ return NET_REDIR; }
"net-tos-redirect"		{ return NET_TOS_REDIR; }
"net-unreachable"		{ return NET_UNREACH; }
"network-unknown"		{ return NET_UNKN; }
"no-room-for-option"		{ return NO_ROOM_OPT; }
"option-missing"		{ return OPT_MISSING; }
"packet-too-big"		{ return PKT_TOO_BIG; }
"parameter-problem"		{ return PARAM_PROB; }
"port-unreachable"		{ return PORT_UNREACH; }
"precedence-unreachable"	{ return PREC_UNREACH; }
"protocol-unreachable"		{ return PROT_UNREACH; }
"host-precedence-unreachable"	{ return HOST_PREC_UNREACH; }

"host-redirect"			{ /* XXX */ return HOST_REDIR; }
"host-tos-redirect"		{ /* XXX */ return HOST_TOS_REDIR; }

"host-unknown"			{ return HOST_UNKN; }
"host-unreachable"		{ return HOST_UNREACH; }
"information-reply"		{ return INFO_REPLY; }
"information-request"		{ return INFO_REQ; }
"mask-reply"			{ return MASK_REPLY; }
"mask-request"			{ return MASK_REQ; }
"reassembly-timeout"		{ return REASS_TIMEOUT; }
"redirect"			{ return REDIR; }
"router-advertisement"		{ return ROUTER_ADV; }
"router-solicitation"		{ return ROUTER_SOL; }
"source-quench"			{ return SRC_QUENCH; }
"source-route-failed"		{ return SRC_ROUTE_FAIL; }
"time-exceeded"			{ return TIME_EXC; }
"timestamp-reply"		{ return TIME_REPLY; }
"timestamp-request"		{ return TIME_REQ; }
"traceroute"			{ return TRACERT; }
"ttl-exceeded"			{ return TTL_EXC; }
"unreachable"			{ return UNREACH; }

"beyond-scope"             	{ /* Destination beyond scope */
				  return BEYOND_SCOPE; }
"destination-unreachable"  	{ /* Destination address is unreachable */
				  return DEST_UNREACH; }
"echo-request"             	{ /* Echo request (ping) */
				  return ECHO_REQUEST; }
"flow-label"               	{ /* Flow label */
				  return FLOW_LABEL; }
"header"                   	{ /* Parameter header problems  */
				  return HEADER; }
"hop-limit"                	{ /* Hop limit exceeded in transit */
				  return HOP_LIMIT; }
"mld-query"                	{ /* Multicast Listener Discovery Query */
				  return MLD_QUERY; }
"mld-reduction"            	{ /* Multicast Listener Discovery Reduction */
				  return MLD_REDUCTION; }
"mld-report"               	{ /* Multicast Listener Discovery Report */
				  return MLD_REPORT; }
"nd-na"                    	{ /* Neighbor discovery neighbor advertisements */
				  return ND_NA; }
"nd-ns"                    	{ /* Neighbor discovery neighbor solicitations */
				  return ND_NS; }
"next-header"              	{ /* Parameter next header problems  */
				  return NEXT_HEADER; }
"no-admin"                 	{ /* Administration prohibited destination */
				  return NO_ADMIN; }
"no-route"                 	{ /* No route to destination */
				  return NO_ROUTE; }
"packet-too-big"           	{ /* Packet too big */
				  return PKT_TOO_BIG; }
"parameter-option"         	{ /* Parameter option problems */
				  return PARAM_OPTION; }
"parameter-problem"        	{ /* All parameter problems */
				  return PARAM_PROB; }
"port-unreachable"         	{ /* Port unreachable */
				  return PORT_UNREACH; }
"reassembly-timeout"       	{ /* Reassembly timeout */
				  return REASS_TIMEOUT; }
"renum-command"            	{ /* Router renumbering command */
				  return RENUM_CMD; }
"renum-result"             	{ /* Router renumbering result */
				  return RENUM_RES; }
"renum-seq-number"         	{ /* Router renumbering sequence number reset */
				  return RENUM_SEQ_NR; }
"router-advertisement"     	{ /* Neighbor discovery router advertisements */
				  return ROUTER_ADV; }
"router-renumbering"       	{ /* All router renumbering */
				  return ROUTER_RENUM; }
"router-solicitation"      	{ /* Neighbor discovery router solicitations */
				  return ROUTER_SOL; }
"routing"                  	{ /* Routing header */
				  return ROUTING; }
"undetermined-transport"	{ /* Transport cannot be determined or is missing */
				  return UNDET_TRAN; }
"sequence"                 	{ /* Sequence number for this entry */
				  return SEQUENCE; }
"time-exceeded"            	{ /* All time exceeded */
				  return TIME_EXCEED; }

"precedence"			{ return PRECEDENCE; }
"critical"			{ return PREC_CRITICAL; }
"flash"				{ return PREC_FLASH; }
"flash-override"		{ return PREC_FLASH_OVERR; }
"immediate"			{ return PREC_IMMED; }
"internet"			{ return PREC_INET; }
"network"			{ return PREC_NET; }
"priority"			{ return PREC_PRIO; }
"routine"			{ return PREC_ROUTINE; }

"reflect"			{ return REFLECT; }

"tos"				{ return TOS; }
"max-reliability"		{ return TOS_MAX_REL; }
"max-throughput"		{ return TOS_MAX_THRPUT; }
"min-delay"			{ return TOS_MIN_DELAY; }
"min-monetary-cost"		{ return TOS_MIN_MONET_COST; }
"normal"			{ return TOS_NORMAL; }


"bgp"			{ /* Border Gateway Protocol (179) */
                  	  yylval.string_n = strdup(yytext);
			  return BGP; }
"chargen"		{ /* Character generator (19) */
                  	  yylval.string_n = strdup(yytext);
			  return CHARGEN; }
"cmd"			{ /* Remote commands (rcmd, 514) */
                  	  yylval.string_n = strdup(yytext);
			  return CMD; }
"daytime"		{ /* Daytime (13) */
                  	  yylval.string_n = strdup(yytext);
			  return DAYTIME; }
"discard"		{ /* Discard (9) */
                  	  yylval.string_n = strdup(yytext);
			  return DISCARD; }
"domain"		{ /* Domain Name Service (53) */
                  	  yylval.string_n = strdup(yytext);
			  return DOMAIN; }
"echo"			{ /* Echo (7) */
                  	  yylval.string_n = strdup(yytext);
			  return ECHO; }
"exec"			{ /* Exec (rsh, 512) */
                  	  yylval.string_n = strdup(yytext);
			  return EXEC; }
"finger"		{ /* Finger (79) */
                  	  yylval.string_n = strdup(yytext);
			  return FINGER; }
"ftp"			{ /* File Transfer Protocol (21) */
                  	  yylval.string_n = strdup(yytext);
			  return FTP; }
"ftp-data"		{ /* FTP data connections (used infrequently, 20) */
                  	  yylval.string_n = strdup(yytext);
			  return FTP_DATA; }
"gopher"		{ /* Gopher (70) */
                  	  yylval.string_n = strdup(yytext);
			  return GOPHER; }
"hostname"		{ /* NIC hostname server (101) */
                  	  yylval.string_n = strdup(yytext);
			  return HOSTNAME; }
"ident"			{ /* Ident Protocol (113) */
                  	  yylval.string_n = strdup(yytext);
			  return IDENT; }
"irc"			{ /* Internet Relay Chat (194) */
                  	  yylval.string_n = strdup(yytext);
			  return IRC; }
"klogin"		{ /* Kerberos login (543) */
                  	  yylval.string_n = strdup(yytext);
			  return KLOGIN; }
"kshell"		{ /* Kerberos shell (544) */
                  	  yylval.string_n = strdup(yytext);
			  return KSHELL; }
"login"			{ /* Login (rlogin, 513) */
                  	  yylval.string_n = strdup(yytext);
			  return LOGIN; }
"lpd"			{ /* Printer service (515) */
                  	  yylval.string_n = strdup(yytext);
			  return LPD; }
"nntp"			{ /* Network News Transport Protocol (119) */
                  	  yylval.string_n = strdup(yytext);
			  return NNTP; }
"pim-auto-rp"		{ /* PIM Auto-RP (496) */
                  	  yylval.string_n = strdup(yytext);
			  return PIM_AUTO_RP; }
"pop2"			{ /* Post Office Protocol v2 (109) */
                  	  yylval.string_n = strdup(yytext);
			  return POP2; }
"pop3"			{ /* Post Office Protocol v3 (110) */
                  	  yylval.string_n = strdup(yytext);
			  return POP3; }
"smtp"			{ /* Simple Mail Transport Protocol (25) */
                  	  yylval.string_n = strdup(yytext);
			  return SMTP; }
"sunrpc"		{ /* Sun Remote Procedure Call (111) */
                  	  yylval.string_n = strdup(yytext);
			  return SUNRPC; }
"syslog"		{ /* Syslog (514) */
                  	  yylval.string_n = strdup(yytext);
			  return SYSLOG; }
"tacacs"		{ /* TAC Access Control System (49) */
                  	  yylval.string_n = strdup(yytext);
			  return TACACS; }
"talk"			{ /* Talk (517) */
                  	  yylval.string_n = strdup(yytext);
			  return TALK; }
"telnet"		{ /* Telnet (23) */
                  	  yylval.string_n = strdup(yytext);
			  return TELNET; }
"time"			{ /* Time (37) */
                  	  yylval.string_n = strdup(yytext);
			  return TIME; }
"uucp"			{ /* Unix-to-Unix Copy Program (540) */
                  	  yylval.string_n = strdup(yytext);
			  return UUCP; }
"whois"			{ /* Nicname (43) */
                  	  yylval.string_n = strdup(yytext);
			  return WHOIS; }
"www"			{ /* World Wide Web (HTTP, 80) */
                  	  yylval.string_n = strdup(yytext);
			  return WWW; }


"biff"			{ /* Biff (mail notification, comsat, 512) */
                  	  yylval.string_n = strdup(yytext);
			  return BIFF; }
"bootpc"		{ /* Bootstrap Protocol (BOOTP) client (68) */
                  	  yylval.string_n = strdup(yytext);
			  return BOOTPC; }
"bootps"		{ /* Bootstrap Protocol (BOOTP) server (67) */
                  	  yylval.string_n = strdup(yytext);
			  return BOOTPS; 

/* DISCARD */ 

			}
"dnsix"			{ /* DNSIX security protocol auditing (195) */
                  	  yylval.string_n = strdup(yytext);
			  return DNSIX; 

/* DOMAIN */ 

			}
"echo"			{ /* Echo (7) */
                  	  yylval.string_n = strdup(yytext);
			  return ECHO; }
"isakmp"		{ /* Internet Security Association and Key Management Protocol (500) */
                  	  yylval.string_n = strdup(yytext);
			  return ISAKMP; }
"mobile-ip"		{ /* Mobile IP registration (434) */
                  	  yylval.string_n = strdup(yytext);
			  return MOBILE_IP; }
"nameserver"		{ /* IEN116 name service (obsolete, 42) */
                  	  yylval.string_n = strdup(yytext);
			  return NAMESERVER; }
"netbios-dgm"		{ /* NetBios datagram service (138) */
                  	  yylval.string_n = strdup(yytext);
			  return NETBIOS_DGM; }
"netbios-ns"		{ /* NetBios name service (137) */
                  	  yylval.string_n = strdup(yytext);
			  return NETBIOS_NS; }
"netbios-ss"		{ /* NetBios session service (139) */
                  	  yylval.string_n = strdup(yytext);
			  return NETBIOS_SS; }
"ntp"			{ /* Network Time Protocol (123) */
                  	  yylval.string_n = strdup(yytext);
			  return NTP; }
"pim-auto-rp"		{ /* PIM Auto-RP (496) */
                  	  yylval.string_n = strdup(yytext);
			  return PIM_AUTO_RP; }
"rip"			{ /* Routing Information Protocol (router, in.routed, 520) */
                  	  yylval.string_n = strdup(yytext);
			  return RIP; }
"snmp"			{ /* Simple Network Management Protocol (161) */
                  	  yylval.string_n = strdup(yytext);
			  return SNMP; }
"snmptrap"		{ /* SNMP Traps (162) */
                  	  yylval.string_n = strdup(yytext);
			  return SNMPTRAP; }
"sunrpc"		{ /* Sun Remote Procedure Call (111) */
                  	  yylval.string_n = strdup(yytext);
			  return SUNRPC; }
"syslog"		{ /* System Logger (514) */
                  	  yylval.string_n = strdup(yytext);
			  return SYSLOG; 

/* udp tacacs port is the same as tcp */

			}


"talk"			{ /* Talk (517) */
                  	  yylval.string_n = strdup(yytext);
			  return TALK; }
"tftp"			{ /* Trivial File Transfer Protocol (69) */
                  	  yylval.string_n = strdup(yytext);
			  return TFTP; }
"time"			{ /* Time (37) */
                  	  yylval.string_n = strdup(yytext);
			  return TIME; }
"who"			{ /* Who service (rwho, 513) */
                  	  yylval.string_n = strdup(yytext);
			  return WHO; }
"xdmcp"			{ /* X Display Manager Control Protocol (177) */
                  	  yylval.string_n = strdup(yytext);
			  return XDMCP; }


"af11"			{
			  return AF11;
			}
"af12"			{
			  return AF12;
			}
"af13"			{
			  return AF13;
			}
"af21"			{
			  return AF21;
			}
"af22"			{
			  return AF22;
			}
"af23"			{
			  return AF23;
			}
"af31"			{
			  return AF31;
			}
"af32"			{
			  return AF32;
			}
"af33"			{
			  return AF33;
			}
"af41"			{
			  return AF41;
			}
"af42"			{
			  return AF42;
			}
"af43"			{
			  return AF43;
			}
"cs1"			{
			  return CS1;
			}
"cs2"			{
			  return CS2;
			}
"cs3"			{
			  return CS3;
			}
"cs4"			{
			  return CS4;
			}
"cs5"			{
			  return CS5;
			}
"cs6"			{
			  return CS6;
			}
"cs7"			{
			  return CS7;
			}
"default"		{
			  return DEFAULT;
			}
"ef"			{
			  return EF;
			}

(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?) {
                  yylval.string_n = strdup(yytext);
                  return IPV4ADDR;
		}

[a-z0-9\-\.]* 	{
                  yylval.string_n = strdup(yytext);
		  return LOWER_STR;
		}
[A-Za-z()0-9,'_=\-]*	{
                  yylval.string_n = strdup(yytext);
                  return REMARK_STR;
                }

([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4} {
		  /* idea and parts of IPv6 regular expressions were taken from http://www.regexlib.com/ (author: Glynn Beeken) */
		  /* xxxx:yyyy:zzzz:aaaa:bbbb:cccc:dddd:eeee */
		  yylval.string_n = strdup(yytext);
		  debug(DEBUG4, "lex", "ipv6 addr full");
		  return IPV6ADDR;
		}

[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){5}::[0-9A-Fa-f]{1,4} {
		  yylval.string_n = strdup(yytext);
		  debug(DEBUG4, "lex", "ipv6 containing :: (1)");
		  return IPV6ADDR;
		}

[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){4}::[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,1} {
		  yylval.string_n = strdup(yytext);
		  debug(DEBUG4, "lex", "ipv6 containing :: (2)");
		  return IPV6ADDR;
		}

[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){3}::[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,2} {
		  yylval.string_n = strdup(yytext);
		  debug(DEBUG4, "lex", "ipv6 containing :: (3)");
		  return IPV6ADDR;
		}

[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){2}::[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,3} {
		  yylval.string_n = strdup(yytext);
		  debug(DEBUG4, "lex", "ipv6 addr containing :: (4)");
		  return IPV6ADDR;
		}

[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}::[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,4}) {
		  yylval.string_n = strdup(yytext);
		  debug(DEBUG4, "lex", "ipv6 containing :: (5)");
		  return IPV6ADDR;
		}

[0-9A-Fa-f]{1,4}::[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,5} {
		  yylval.string_n = strdup(yytext);
		  debug(DEBUG4, "lex", "ipv6 containing :: (6)");
		  return IPV6ADDR;
		}

[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,6}:: {
		  yylval.string_n = strdup(yytext);
		  debug(DEBUG4, "lex", "ipv6 addr ending with ::");
		  return IPV6ADDR;
		}

"::"		{
		  yylval.string_n = strdup(yytext);
		  debug(DEBUG4, "lex", "ipv6 addr ::");
		  return IPV6ADDR;
		}

::[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,6} {
		  yylval.string_n = strdup(yytext);
		  debug(DEBUG4, "lex", "ipv6 addr beggining with ::");
		  return IPV6ADDR;
		}

([0-9A-Fa-f]{1,4}:){6}((25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{0,2})\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{0,2}) {
		  yylval.string_n = strdup(yytext);
		  debug(DEBUG4, "lex", "ipv6 ipv4 compatible XXX addr");
		  return IPV6ADDR;
		}

"!".*\n         { lex_line++; } /* comment */
\n              { lex_line++; }
.               { 
		  snprintf(errstr, sizeof(errstr), "illegal token '%s'", 
		  		yytext);
		  yyerror(errstr); 
		  return(1);
		}

%%
