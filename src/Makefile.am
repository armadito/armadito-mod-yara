AUTOMAKE_OPTIONS=subdir-objects

modulesdir=$(libdir)/armadito/modules
modules_LTLIBRARIES=yara.la

yara_la_SOURCES=yaramod.c

yara_la_LDFLAGS= -module -avoid-version -export-symbols "$(srcdir)/yara.sym"
yara_la_CFLAGS= @LIBARMADITO_CFLAGS@
yara_la_LIBADD= @LIBARMADITO_LIBS@
yara_la_CFLAGS+= @LIBYARA_CFLAGS@
yara_la_LIBADD+= @LIBYARA_LIBS@

install-exec-hook:
	-rm -f "$(DESTDIR)$(modulesdir)"/yara.la "$(DESTDIR)$(modulesdir)"/yara.a

install-data-hook:
	-rm -f "$(DESTDIR)$(modulesdir)"/yara.la "$(DESTDIR)$(modulesdir)"/yara.a

EXTRA_DIST=yara.sym
