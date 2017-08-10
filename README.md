# goodns (ɡo͝odnəs)

This program interrogates Google Suggestions to passively discover sub-domains for a given domain. Currently there are two modes of operation:

1. Prefix brute-force mode
2. Word list mode

Prefix brute-force mode uses a prefix length parameter `-c <i>` to specify the length of the sub-domain prefix.

Word list mode reads words from a file `-w <file>` to specify the sub-domain prefix.

You can search across many different Google TLDs using the `-l <tld>` parameter or search across all of the supported TLDs by excluding the parameter completely (not recommended).

Be careful using this script aggressively. You will get banned by Google eventually if you don't take your time running it :)
