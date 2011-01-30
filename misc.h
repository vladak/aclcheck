/*
  misc definitions, protos for Cisco ACL checker

  Vladimir Kotal <vlada@devnull.cz>, 2004
 */

#ifndef _MISC_H_
#define _MISC_H_

#define NAMEFMT         "[%s] "         /* writing style for debug() */

#define MAX_LOGBUFSIZ	220     	/* max length of log buffer */

#define EXIT_FAILURE	1		/* exit error code for lex */


typedef enum {
  INFO   = -3,  /* info messages on stderr */
  ERROR = -1,   /* report error occured */
  FATAL = -2,   /* unhandable exception, exit */
  DEBUG1 = 1,   /* main loop events */
  DEBUG2 = 2,   /* other */
  DEBUG3 = 3,   /* server related */
  DEBUG4 = 4    /* parser related */
} logprio;


/* ruleset types */
#define RSET_NONE		0x20
#define RSET_EXTENDED		0x40
#define RSET_IPV6		0x80


#define EQ_PORTSPEC	1
#define EMPTY_PORTSPEC	2
#define RANGE_PORTSPEC	3
/* struct reflecting port specification 
   for eq,gt,lt keywords, 'low' member is set to port number
*/
typedef struct portspec_s {
  int type;
  int low;
  int high;
} portspec_t;


/* enum values for better error guessing heuristics */
typedef enum {
	ACL_KEYW_STATE,
	ACL_NUM_STATE,
	PERMIT_DENY_STATE,
	PROTO_STATE,
	SRC_SPEC_STATE,
	DST_SPEC_STATE,
	PROTO_QUALIF_STATE,
	LOGGING_STATE
} state_t;

/* macros */
#define PRANGE_CHECK(lower,higher)					\
	if (lower > higher) {						\
	  yyerror("lower port should be first in range specifier");	\
	  return(1);							\
	}

/* function protos */
void debug(logprio prio, char *name, const char *fmt, ...);
int yyerror(char *fmt, ...);
int valid_ipaddr(int pf, char *ipstr, int portnr); 
int valid_portnr(int portnr);

int load_config(char *filename);	/* from extacl.y */
int check_servname(char *servname);


#endif
