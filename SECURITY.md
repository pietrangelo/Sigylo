# Security

Found a weakness in Sigylo or in the service at https://sigylo.net? Please write to
privacy@sigylo.net (Italian or English) before telling anyone else, or open a
[private security advisory](https://github.com/pietrangelo/Sigylo/security/advisories/new)
on GitHub. Say what you found and how to reproduce it.

In scope: anything that lets someone read, change, keep or destroy a secret they were not
given, learn who sent or received it, run code in the page or the app, or stop the
service for everyone. Out of scope: reports from automated scanners without a working
attack, and the known limits written down in CLAUDE.md ("Known limit").

Please never test against secrets that are not yours, and never flood the live service:
run it locally instead (`bash scripts/e2e.sh`).
