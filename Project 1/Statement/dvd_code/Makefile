##############################################################################
# 
# INFO0045: Assignment #1
# 
# Makefile 
#
##############################################################################

target: info0045

JAVA            = java
JAVAC           = javac
RM              = rm
CP              = cp

JAVASRC		= \
		info0045/DVDManufacturer.java \
		info0045/DVDPlayer.java \
		info0045/KeyTree.java \
		info0045/PlayerKeys.java \

JAVAOBJS	= $(JAVASRC:.java=.class)

.SUFFIXES:	.class .java

.java.class: $*.java
	$(JAVAC) $(JAVAFLAGS) $*.java

clean:
	$(RM) $(JAVAOBJS)

backup:
	$(CP) $(JAVASRC) $(BACKUPDIR)

info0045: $(JAVAOBJS)
