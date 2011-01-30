#
# simple makefile for Cisco ACL checker
#
# Vladimir Kotal, 2004-2005
#

ACLCHECK=aclcheck
ACLTEST=acltest

CC=gcc
CFLAGS=-Wall -ggdb -DDEBUG
BISON=bison
BISON_FLAGS=-y --debug -v -d
LEX=flex
LEX_FLAGS=-l -t
INSTALL=install
PREFIX=/usr/local
OWNER=root
GROUP=wheel
MODE=0755
SOLARIS_LIBS=-lnsl -lsocket

OBJDIR=objects
BUILDDIR=build
REGRDIR=regress

#DISTDIR=$$HOME/Public/webt/aclcheck
DISTDIR=$$HOME/Documents/webt/aclcheck

DIST_SRCFILES=	Makefile aclcheck.c acltest.txt config.h extacl.y lex.l \
		misc.c misc.h stdacl.y
SAMPL_DIR=samples
DIST_SAMPLES=	$(SAMPL_DIR)/dscp.acl $(SAMPL_DIR)/icmp.acl \
		$(SAMPL_DIR)/ipv6.acl $(SAMPL_DIR)/port.acl \
		$(SAMPL_DIR)/proto.acl $(SAMPL_DIR)/sample.acl \
		$(SAMPL_DIR)/tcp.acl $(SAMPL_DIR)/udp.acl
DIST_DOCS=LICENSE README TODO.txt aclcheck.1
DIST_SCRIPTS=yysed

ACLCHECKDIR=$(ACLCHECK)
INDEXHTML="$(DISTDIR)/index.html"

COMMON_OBJS= 	$(OBJDIR)/extacl.o \
		$(OBJDIR)/lex.o \
		$(OBJDIR)/misc.o 

EXCLF=		$(ACLCHECK).excl

all: setup $(BUILDDIR)/$(ACLCHECK)

$(ACLTEST)-target: $(BUILDDIR)/$(ACLTEST)

setup:
	@if test ! -d $(OBJDIR); then mkdir $(OBJDIR); fi
	@if test ! -d $(BUILDDIR); then mkdir $(BUILDDIR); fi

$(BUILDDIR)/$(ACLCHECK): $(COMMON_OBJS) $(OBJDIR)/$(ACLCHECK).o
	$(CC) -o $(BUILDDIR)/$(ACLCHECK) $(COMMON_OBJS) $(OBJDIR)/$(ACLCHECK).o
#	$(CC) -o $(BUILDDIR)/$(ACLCHECK) $(COMMON_OBJS) $(SOLARIS_LIBS)

$(BUILDDIR)/$(ACLTEST): $(COMMON_OBJS) $(OBJDIR)/acltest.o
	$(CC) -o $(BUILDDIR)/$(ACLTEST) $(COMMON_OBJS) $(OBJDIR)/acltest.o

lex.c: lex.l
	$(LEX) $(LEX_FLAGS) lex.l > lex.c

stdacl.c stdacl.h: stdacl.y
	$(BISON) $(BISON_FLAGS) -o stdacl.c stdacl.y
	sh yysed stdacl.c std

extacl.c extacl.h: extacl.y
	$(BISON) $(BISON_FLAGS) -o extacl.c extacl.y
	sh yysed extacl.c ext

$(OBJDIR)/extacl.o: extacl.c 
	$(CC) $(CFLAGS) -c extacl.c -o $(OBJDIR)/extacl.o

$(OBJDIR)/lex.o: lex.c
	$(CC) $(CFLAGS) -c lex.c -o $(OBJDIR)/lex.o

$(OBJDIR)/misc.o: misc.c misc.h
	$(CC) $(CFLAGS) -c misc.c -o $(OBJDIR)/misc.o

$(OBJDIR)/$(ACLCHECK).o: $(ACLCHECK).c
	$(CC) $(CFLAGS) -c $(ACLCHECK).c -o $(OBJDIR)/$(ACLCHECK).o

$(OBJDIR)/$(ACLTEST).o: $(ACLTEST).c
	$(CC) $(CFLAGS) -c $(ACLTEST).c -o $(OBJDIR)/$(ACLTEST).o

regress: all
	@for acl in `ls -1 $(REGRDIR)/pass/*.acl`; do \
	  $(BUILDDIR)/$(ACLCHECK) $$acl; \
	  if [ $$? -ne 0 ]; then \
	    echo "$$acl check failed"; \
	    exit 1; \
	  fi; \
	done
	@for acl in `ls -1 $(REGRDIR)/fail/*.acl`; do \
	  $(BUILDDIR)/$(ACLCHECK) $$acl 2>/dev/null; \
	  if [ $$? -ne 1 ]; then \
	    echo "$$acl check should have failed, but did not"; \
	    exit 1; \
	  fi; \
	done
	@echo "regress tests OK"

dist: regress dist-clean
	tar czf tmp.tar.gz \
		$(DIST_SRCFILES) \
		$(DIST_SAMPLES) \
		$(DIST_SCRIPTS) \
		$(DIST_DOCS)
	mkdir -p tmp/$(ACLCHECK)
	mv tmp.tar.gz tmp/$(ACLCHECK)
	cd tmp/$(ACLCHECK) && tar xfz tmp.tar.gz && rm -f tmp.tar.gz
	cd tmp && tar cfz $(ACLCHECK).tar.gz $(ACLCHECK)
	mv tmp/$(ACLCHECK).tar.gz $(DISTDIR); 
	sh snapdate.sh $(INDEXHTML)
	cd $(DISTDIR); cvs commit -m 'new dist'
	rm -rf tmp

dist-clean: clean

man: aclcheck.1
	nroff -man aclcheck.1 | less

# this can be handled by port's Makefile
install:
	$(INSTALL) -o $(OWNER) -g $(GROUP) -m $(MODE) \
		$(BUILDDIR)/$(ACLCHECK) $(PREFIX)/bin/$(ACLCHECK)

clean:
	rm -rf build objects
	rm -f extacl.c extacl.h lex.c
	rm -f *.o *.core
