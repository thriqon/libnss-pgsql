# the compilers
# everything you need is in package debiandoc-sgml
TXTC=debiandoc2text
TOVC=debiandoc2textov
TEXC=debiandoc2latex
TEXIC=debiandoc2texinfo
HTMLC=debiandoc2html
PSC=debiandoc2latexps
PDFC=debiandoc2latexpdf

OPTS=-l en

SRCS=$(wildcard *.sgml)
TXTDOCS=$(SRCS:.sgml=.txt)
TOVDOCS=$(SRCS:.sgml=.tov)
TEXDOCS=$(SRCS:.sgml=.tex)
TEXIDOCS=$(SRCS:.sgml=.info)
HTMLDOCS=$(SRCS:.sgml=.html)
PSDOCS=$(SRCS:.sgml=.ps)
PDFDOCS=$(SRCS:.sgml=.pdf)
DOCS=$(TXTDOCS) $(TOVDOCS) $(TEXDOCS) $(TEXIDOCS) $(HTMLDOCS) $(PSDOCS) $(PDFDOCS)

.PHONY:default text tov latex texi html postscript pdf all clean

default:text

text:$(TXTDOCS)

textov:$(TOVDOCS)

latex:$(TEXDOCS)

info:$(TEXIDOCS)

html:$(HTMLDOCS)

postscript:$(PSDOCS)

pdf:$(PDFDOCS)

all:$(DOCS)

%.txt:%.sgml
	$(TXTC) $(OPTS) $<

%.tov:%.sgml
	$(TOVC) $(OPTS) $<

%.tex:%.sgml
	$(TEXC) $(OPTS) $<

%.texinfo:%.sgml
	$(TEXIC) $(OPTS) $<

%.html:%.sgml
	$(HTMLC) $(OPTS) $<

%.ps:%.sgml
	$(PSC) $(OPTS) $<

%.pdf:%.sgml
	$(PDFC) $(OPTS) $<

clean:
	rm -rf $(DOCS)