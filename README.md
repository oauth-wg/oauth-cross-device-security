# Cross-Device Flow Security BCP

Written in markdown for the mmark processor.

Compiling
using Docker
From the root of this repository, run

docker run -v `pwd`:/data danielfett/markdown2rfc main.md
(see https://github.com/oauthstuff/markdown2rfc)

without Docker
compile using mmark and xml2rfc: mmark main.md > draft.xml; xml2rfc --html draft.xml
