TARGETS	= nss-pgsql.html

all html: $(TARGETS)

install-data-local: $(TARGETS)
	$(mkinstalldirs) $(DESTDIR)/$(prefix)/doc
	$(INSTALL-DATA) nss-pgsql.html $(DESTDIR)/$(prefix)/doc
	$(INSTALL-DATA) $(srcdir)/caution.png $(DESTDIR)/$(prefix)/doc

clean-local:
	rm -f $(TARGETS)

nss-pgsql.html: config.xsl nss-pgsql.xml
	xmlto xhtml-nochunks -m $(srcdir)/config.xsl $(srcdir)/nss-pgsql.xml

