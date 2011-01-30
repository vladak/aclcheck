/*
   misc routines for parser

   Vladimir Kotal <vlada@devnull.cz>, 2004
 */


#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>

#include "misc.h"

extern int debug_level;
extern int state;

/* for yyerror() */
extern int lex_line;
extern int acl_line;
extern int errors;

/* names of parser states */
#define MAX_ERRMSG_LEN 		40
char states[][MAX_ERRMSG_LEN] = {
	{ "access-list keyword" },
	{ "access list number" },
	{ "permit or deny keyword" },
	{ "protocol keyword" },
	{ "source specification" },
	{ "destination specification" },
	{ "protocol qualifier" },
	{ "logging keyword" },
	{ (int)NULL }
};


/**
  check port number validity

  \param XXX
  \return 0 on failure or 1 on success
 */
int valid_portnr(int portnr) {

  /* XXX constants */
  if ((portnr >= 0) && (portnr <= 65535)) 
    return(1);

  return(0);
}


/**
  check IP address validity

  \param address family
  \param string containing ip address
  \return 0 on failure or 1 on success
 */
int valid_ipaddr(int pf, char *ipstr, int portnr) {

  /* for getaddrinfo() */
  struct addrinfo hints, *restmp, *res0;
  char portstr[5];
  int error;

  if (portnr != -1)
    snprintf(portstr, sizeof(portstr), "%d", portnr);

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = pf;
  // XXX
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  if (portnr == -1)
    error = getaddrinfo(ipstr, NULL, &hints, &res0);
  else
    error = getaddrinfo(ipstr, portstr, &hints, &res0);

  if (error) {
    // XXX debug()
    freeaddrinfo(res0);
    return(0);
  }

  for (restmp = res0; restmp; restmp = restmp->ai_next) {
    switch (restmp->ai_family) {
	case AF_INET:
		if (pf == AF_INET)
		  return(1);
		break;
	case AF_INET6:
		if (pf == AF_INET6)
		  return(1);
		break;
	default:
		// debug("unknown address family");
		freeaddrinfo(res0);
		return(0);
    }
  }

  freeaddrinfo(res0);
  return(0);
}


int yyerror(char *fmt, ...)
{
        va_list ap;
	int line;

        errors = 1;

        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);

	if (acl_line == 0)
	  acl_line = lex_line; /* no acl was parsed yet */

	if (state == -1)
	  line = lex_line;
	else
	  line = lex_line > acl_line ? acl_line : lex_line;
	  /* XXX line = acl_line; */

        fprintf(stderr, " [on line %d]", line);

	if (state != -1) 
 	  fprintf(stderr, " (%s ?)\n", states[state + 1]);
	else
	  fprintf(stderr, "\n");

        va_end(ap);
        return (0);
}


/*  
 * print debug message
 *
 * if we are forked, log it via syslog, 
 * otherwise print it on stderr
 */
void debug_print(FILE *stream, const char *name, va_list ap,
        const char *fmt){

  char logbuf[MAX_LOGBUFSIZ];

  fprintf(stream, NAMEFMT, name);
  memset(logbuf,'\0',sizeof(logbuf));
  vsnprintf(logbuf, sizeof(logbuf), fmt, ap); 
  fprintf(stream, "%s [%d]\n", logbuf, lex_line);
}


/*
 * debug output
 */
void debug(logprio prio, char *name, const char *fmt, ...){
  va_list ap;

  va_start(ap, fmt);

  switch(prio){
        case ERROR:
		if (debug_level > 0)
                  debug_print(stderr, name, ap, fmt);
                break;

        case FATAL:
                debug_print(stderr, name, ap, fmt);
                exit(EXIT_FAILURE);
                break;

        default:
                if ((int)prio <= debug_level){
                  debug_print(stderr, name, ap, fmt);
                }  
                break;
  }
  
  va_end(ap);
}


/*
  this routine is prepared for ACL evaluation against given packet
  specification

  to be used in the future

 */
int check_servname(char *servname) {
#if 0
  struct servent *se;
  int portval;

  /* XXX search does not need to match protocol */
  if ((se = getservbyname($1, NULL)) == 0) {
    yyerror("invalid port specification: '%s'", $1);
    return(1);
  }

  portval = se->s_port;

  if (!valid_portnr(portval)) {
    yyerror("invalid port number: %d", $1);
    return(1);
  }
#endif

  return(1);
}

