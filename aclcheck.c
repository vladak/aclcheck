/*
  Cisco access list checker stub
    - parsing is done via yyextparse() in extacl.y:load_config()

  Vladimir Kotal <vlada@devnull.cz>, 2004

 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "config.h"
#include "misc.h"

int debug_level = 0;		/* global debug level */


/* print usage to stdout */
void print_usage(char *progname) {

    fprintf(stdout, "usage: %s [-v] <aclfile>\n", progname);
    fprintf(stdout, "-v\tdebug flag, can be multiplied\n");

}


/* parse options and run parser, reports errors */
int main(int argc, char**argv){

  int ch;
  char *progname;
  
  extern int optind;
  
  progname = argv[0];
  
  while ((ch = getopt(argc, argv, "v")) != -1) {
    switch (ch) {
      case 'v':
        debug_level++;
        break;

      default:
	print_usage(progname);
	exit(1);
    }
  }
  argc -= optind;
  argv += optind;
  
  if (argc != 1){
    print_usage(progname);
    exit(1);
  }

  if (!(load_config(argv[0]))) {
    debug(ERROR, "aclcheck", "cannot parse config file");
    exit(1);
  }

  return(0);
}
