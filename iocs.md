N3 — Nemotodes: IOCs and Network Artifacts
Indicators below are defanged for safe presentation. Distinguish the primary suspicious indicators from contextual artifacts; not every observed hostname or address should automatically be blocked.
Primary suspicious indicators
Type	Indicator	Context	Confidence
IPv4	194.180.191[.]64	External endpoint for repeated HTTP POST requests consistent with NetSupport-like C2	High
URL	hxxp://194.180.191[.]64/fakeurl.htm	Observed POST path with NetSupport-like command fields	High
Domain	modandcrackedapk[.]com	Queried by the affected host and observed as TLS SNI; encrypted contents unknown	Suspicious; relationship to NetSupport C2 unconfirmed
IPv4	193.42.38[.]139	Destination of TLS session with SNI modandcrackedapk.com	Associated with suspicious session


Supporting network artifacts (not standalone malicious IOCs)
Type	Artifact	Context
HTTP User-Agent	NetSupport Manager/1.3	Present in requests to 194.180.191[.]64
HTTP Server header	NetSupport Gateway/1.8 (Windows NT)	Present in responses from the external endpoint
HTTP fields	CMD=POLL, INFO=1, ACK=1, CMD=ENCD, ES=1, DATA=...	Observed in NetSupport-like request/response traffic; DATA contents were not decoded
URL	hxxp://geo.netsupportsoftware[.]com/location/loca.asp	NetSupport geolocation lookup; treated as contextual, not malicious by itself
Internal host	10.11.26.183	Affected endpoint; internal asset, not an external block IOC
Hostname	DESKTOP-B8TQK49	Hostname associated with the affected endpoint
Internal server	10.11.26.3 (NEMOTODES-DC)	Domain controller involved in SMB/SAMR/MS-EFSR activity


Not confirmed / excluded from primary IOC list
- No malware file hash was independently established from the reviewed notes.
- classicguard.com and its observed IP were not promoted to primary IOCs because the investigation notes did not establish a malicious relationship.
- 104.26.1.231 and geo.netsupportsoftware.com were related to a geolocation lookup; the request is not treated as a standalone malicious indicator.
- No evidence in the reviewed notes confirms that modandcrackedapk.com delivered a file or participated in the NetSupport C2 session.
- Exfiltration was not confirmed; opaque POST data is not sufficient evidence by itself.
