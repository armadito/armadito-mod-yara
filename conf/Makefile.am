confdir=$(sysconfdir)/armadito/conf.d
conf_DATA=yara.conf

EDIT = sed \
        -e 's,@localstatedir\@,$(localstatedir),g' 

%.conf: Makefile $(srcdir)/%.conf.in
	rm -f $*.conf $*.conf.tmp
	$(EDIT) $(srcdir)/$*.conf.in >$*.conf.tmp
	mv $*.conf.tmp $*.conf

EXTRA_DIST=yara.conf.in

CLEANFILES=yara.conf
