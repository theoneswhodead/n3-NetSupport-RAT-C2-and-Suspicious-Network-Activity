# Incident Report: Nemotodes — NetSupport RAT C2 and Suspicious Network Activity

## Summary

On 26 November 2024, internal host `10.11.26.183` (`DESKTOP-B8TQK49`) generated network activity consistent with command-and-control (C2) communication involving NetSupport remote-access software. The strongest evidence is repeated HTTP `POST` traffic to `194.180.191.64` on TCP port `443`, using the URI `/fakeurl.htm`, the User-Agent `NetSupport Manager/1.3`, and the server header `NetSupport Gateway/1.8 (Windows NT)`. The requests contained fields such as `CMD=POLL`, `INFO=1`, `ACK=1`, and `CMD=ENCD`, with an opaque `DATA` value. IDS alerts independently flagged NetSupport RAT C2 activity and check-ins.

The host also resolved and connected to `modandcrackedapk.com` (`193.42.38.139`) over TLS. The application-layer payload was encrypted and could not be interpreted from the available packet review. The domain was flagged by an IDS rule and the analyst's VirusTotal check reported 5/92 detections, which is suspicious context but does not independently establish what the encrypted session carried or prove that it was part of the NetSupport C2 channel.

SMB/SAMR activity, SMBv1-related alerts, and an MS-EFSR `EfsRpcOpenFileRaw` alert were observed between the affected host and the domain controller. These events warrant investigation, but the reviewed network evidence does not confirm successful exploitation, a denial-of-service attack, or a direct causal relationship between the SMB activity and the NetSupport communication.

**Assessment:** High-confidence suspicious NetSupport remote-access/C2 activity from `10.11.26.183`; likely malicious or unauthorized use of NetSupport. The exact initial-access vector, process responsible, successful exploitation of SMB/EFSR, and data exfiltration are not established by the reviewed evidence.

**Confidence:** High for the observed NetSupport-like HTTP C2 pattern; moderate for classifying the separate `modandcrackedapk.com` connection as malicious; low/undetermined for initial access and SMB exploitation.

## Affected Host

|Attribute|Value|
|---|---|
|IP Address|`10.11.26.183`|
|MAC Address|`d0:57:7b:ce:fc:8b`|
|Hostname|`DESKTOP-B8TQK49`|
|Domain|`nemotodes.health`|
|Domain Controller / DNS Server|`10.11.26.3` — `NEMOTODES-DC`|
|Account observed in later SMB context|`Administrator@NEMOTODES` (not confirmed as the interactive user of the affected endpoint)|

The account context is not conclusive: an earlier IPC$ sequence was recorded with a blank/anonymous-looking user field. The network capture alone does not establish which user was interactively logged on to the affected host.

## Timeline

### 2024-11-26 04:49:38 UTC — Windows connectivity test

The host requested `/connecttest.txt` from `www.msftconnecttest.com`.

- Source: `10.11.26.183:53279`
- Destination: `104.117.247.184:80`
- User-Agent: `Microsoft NCSI`
- Assessment: Consistent with a normal Windows network connectivity test; no direct link to the suspicious activity was established.

### 2024-11-26 04:49:41 UTC — TLS connection to Microsoft licensing endpoint

A connection was observed from `10.11.26.183` to `4.149.227.78:443`, with SNI `licensing.mp.microsoft.com` and a Microsoft Azure TLS certificate. An IDS alert reported TLS 1.0, while the analyst's packet notes also recorded TLS 1.2. The negotiated version should be rechecked before making a definitive statement about the session's TLS version. This connection was not linked to the malicious activity.

### 2024-11-26 04:49:55–04:50:05 UTC — SMB/SAMR activity with the domain controller

The host communicated with `10.11.26.3` (`NEMOTODES-DC`) using SMB-related protocols. The reviewed notes recorded network-interface and file-information queries, SAMR operations including `EnumDomains`, `LookupDomain`, `LookupNames`, `OpenUser`, `QueryUserInfo`, `QuerySecurity`, and `GetGroupsForUser`, and a tree connection to `\\NEMOTODES-DC\Shared_Files`. Tree-disconnect and session-logoff requests followed.

SMB2 activity on TCP/445 included an IDS alert for MS-EFSR `EfsRpcOpenFileRaw`. The observed operation is a reason to examine the server response and domain-controller logs, but the alert alone does not prove exploitation or forced authentication.

The analyst also observed SMB2 CREATE requests naming `Desktop.ini` and `AutoRun.inf`. A CREATE request alone does not prove that either file was successfully created or modified; the corresponding response and create disposition would be needed.

### 2024-11-26 04:50:10 UTC — SMBv1 / NetBIOS SMB and IPC$

The host communicated with the domain controller over TCP/139. The alerts included potentially unsafe SMBv1 use, an NTLMSSP/ASN.1 overflow signature, IPC$ share access, and an SMB transaction rule labeled as a possible DoS attempt. `NetServerEnum2` was also observed in the analyst's notes.

These observations confirm that the corresponding protocol operations or patterns were present, but they do not by themselves prove a successful login attempt, exploitation, or denial of service. The relationship between this activity and the later NetSupport-like C2 communication remains unconfirmed.


### 2024-11-26 04:50:10 UTC — TLS connection to `modandcrackedapk.com`

A TLS connection was observed from `10.11.26.183` to `193.42.38.139`, with SNI `modandcrackedapk.com`. The analyst reported additional connections involving several client source ports and encrypted application data, with TCP duplicate acknowledgments, retransmissions, and out-of-order packets.

The traffic may represent substantial encrypted data transfer, but the payload contents and purpose could not be determined from the reviewed packet data. The analyst's VirusTotal check showed 5/92 detections with phishing-related context. This connection is treated as suspicious; no direct relationship to the NetSupport C2 endpoint was established.

### 2024-11-26 04:50:14 UTC — DNS query for suspicious domain

`10.11.26.183` queried `modandcrackedapk.com` via the internal DNS server `10.11.26.3`. An IDS rule flagged the domain as suspicious.

### 2024-11-26 04:50:45 UTC onward — HTTP-based NetSupport C2 pattern

The host sent repeated HTTP POST requests to `http://194.180.191.64/fakeurl.htm` over TCP/443. The reviewed requests included:

- `Host: 194.180.191.64`
- `User-Agent: NetSupport Manager/1.3`
- `Server: NetSupport Gateway/1.8 (Windows NT)` in responses
- Fields such as `CMD=POLL`, `INFO=1`, `ACK=1`, and `CMD=ENCD`
- An opaque `DATA` field whose contents were not decoded

Multiple IDS alerts flagged NetSupport RAT C2 activity, malicious check-ins, HTTP POST on an unusual port, and a NetSupport remote-admin response. The requests were frequent; the analyst noted bursts of several POSTs per second. Traffic was observed in sessions using client source ports `53362` and `53500`, with activity continuing in the reviewed notes until approximately 05:43 UTC.

This pattern, including the URI and User-Agent, is strongly consistent with HTTP-based NetSupport C2 behavior. The small opaque messages do not, by themselves, establish data exfiltration.

### 2024-11-26 04:50:45 UTC — NetSupport geolocation lookup

A GET request to `geo.netsupportsoftware.com/location/loca.asp` was observed. The request included coordinates `33.7488,-84.3877`, and an IDS rule identified it as a NetSupport geolocation lookup. This is consistent with a geolocation function associated with the software; it is supporting context, not a standalone malicious IOC.

### 2024-11-26 05:35:54 UTC — Windows certificate trust-list update check

The host requested a Windows Update trust-list resource from `ctldl.windowsupdate.com`. The server responded `304 Not Modified`. This is consistent with routine Windows certificate trust-list checking and was not linked to the suspicious activity.

### 2024-11-26 05:39:58–05:43:58 UTC — Later SMB activity with the domain controller

A later SMB session between `10.11.26.183` and `10.11.26.3` included repeated file-information queries against domain-policy-related paths, including FileInfo, StreamInfo, extended-attribute, and volume-information requests. The analyst's notes recorded the account context `Administrator@NEMOTODES` during this activity.

This SMB activity overlapped with or occurred near the end of the observed NetSupport-like communication. Temporal proximity alone does not demonstrate that the sessions were generated by the same process or that one caused the other.

## Key Findings

### 1. NetSupport-like HTTP Command and Control

Repeated HTTP POST requests to `194.180.191.64:443/fakeurl.htm`, together with `NetSupport Manager/1.3`, `NetSupport Gateway/1.8 (Windows NT)`, the `CMD=POLL`/`CMD=ENCD` fields, and multiple matching IDS alerts, provide high-confidence evidence of communication consistent with NetSupport RAT C2.

Although the destination uses TCP port 443, the observed application-layer requests are HTTP, not evidence of HTTPS/TLS encryption. The meaning of the opaque `DATA` field was not established.

### 2. Suspicious TLS activity involving `modandcrackedapk.com`

The affected host queried the domain and then connected to `193.42.38.139` with that domain as SNI. IDS rules flagged the DNS and TLS activity, and the analyst's VirusTotal check reported 5/92 detections. The TLS payload remained encrypted, so the file or operation involved cannot be identified from this evidence alone. The connection is kept as a suspicious, separate finding rather than asserted as the delivery path for NetSupport.

### 3. SMB/SAMR/MS-EFSR activity requiring further validation

The host performed domain-controller-facing SMB/SAMR operations and generated alerts for SMBv1, IPC$, NTLMSSP/ASN.1, a possible SMB transaction DoS pattern, and MS-EFSR `EfsRpcOpenFileRaw`. These warrant review of the relevant SMB request/response sequence and domain-controller telemetry. Successful exploitation, credential theft, forced authentication, or a DoS was not confirmed.

### 4. Likely routine background traffic

The Windows connectivity test, Microsoft licensing traffic, certificate trust-list check, and NetSupport geolocation request each have plausible routine explanations. They are not treated as standalone indicators of compromise. The TLS-version discrepancy for the Microsoft licensing connection remains unresolved.

## Alert Triage and Disposition

| Alert / Activity                                                     | Assessment                                                       | Rationale                                                                                                                                                             |
| -------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ET INFO Terse Request for .txt - Likely Hostile                      | Likely benign                                                    | The URI was `/connecttest.txt`, with User-Agent `Microsoft NCSI`, consistent with Windows connectivity checking.                                                      |
| ET INFO Microsoft Connection Test                                    | Benign / expected                                                | Consistent with a Windows connectivity test; no evidence links it to the suspicious activity.                                                                         |
| ET DNS Standard query response, Name Error                           | Informational / unresolved                                       | A DNS negative response is not malicious by itself; the queried name and context would be needed to attribute it.                                                     |
| ET POLICY TLSv1.0 Used in Session                                    | Policy anomaly / unresolved                                      | The alert referenced a Microsoft licensing endpoint, but the working notes also recorded TLS 1.2. Confirm the handshake/version fields before finalizing disposition. |
| ETPRO POLICY MS-EFSR `EfsRpcOpenFileRaw`                             | Suspicious / unconfirmed                                         | MS-EFSR activity was observed over SMB to the domain controller; successful abuse or forced authentication was not established.                                       |
| ET INFO Potentially unsafe SMBv1 protocol in use                     | True positive for SMBv1 use; intent unresolved                   | The traffic used NetBIOS SMB over TCP/139. Legacy protocol use is a security concern, but not proof of exploitation.                                                  |
| GPL NETBIOS SMB Session Setup NTLMSSP Unicode ASN.1 overflow attempt | Suspicious / unconfirmed                                         | The signature matched a packet pattern; successful exploitation was not demonstrated.                                                                                 |
| GPL NETBIOS SMB IPC$ Unicode share access                            | True positive for observed IPC$ access; not inherently malicious | The SMB tree-connect activity was present, but IPC$ access alone does not establish malicious intent.                                                                 |
| GPL NETBIOS SMB transaction Max Data Count of 0 DoS attempt          | Suspicious / unconfirmed                                         | The rule matched an SMB transaction pattern; no successful denial of service was observed in the reviewed evidence.                                                   |
| ET CURRENT_EVENTS ZPHP Domain in DNS Lookup — `modandcrackedapk.com` | True positive for domain query; suspicious                       | The host queried the domain, which was also observed as TLS SNI. The exact payload and intent remain unknown.                                                         |
| ET CURRENT_EVENTS ZPHP Domain in TLS SNI — `modandcrackedapk.com`    | True positive for observed TLS SNI; suspicious                   | The host established TLS communication to `193.42.38.139` using this SNI; payload was encrypted.                                                                      |
| ET POLICY HTTP Request on Unusual Port Possibly Hostile              | True positive for observed HTTP behavior                         | HTTP was sent to TCP/443 at `194.180.191.64`; the destination port does not make the traffic HTTPS.                                                                   |
| ET POLICY HTTP POST on Unusual Port Possibly Hostile                 | True positive for observed HTTP behavior                         | Part of the repeated POST pattern to `/fakeurl.htm`; overlaps with other alerts for the same activity.                                                                |
| ETPRO TROJAN NetSupport RAT CnC Activity                             | True positive                                                    | Supported by the request path, NetSupport User-Agent/server header, command-like fields, and surrounding check-in pattern.                                            |
| ETPRO TROJAN Malicious NetSupport RAT CnC Checkin                    | True positive                                                    | Corroborates the NetSupport-like check-in behavior.                                                                                                                   |
| ET POLICY HTTP traffic on port 443 (POST)                            | True positive for observed HTTP behavior                         | Describes the same HTTP POST activity on TCP/443; not a separate incident.                                                                                            |
| ET INFO NetSupport Remote Admin Checkin                              | True positive                                                    | Consistent with the observed NetSupport-like check-in pattern.                                                                                                        |
| ET POLICY NetSupport GeoLocation Lookup Request                      | True positive for lookup activity; not a standalone IOC          | The request to `geo.netsupportsoftware.com/location/loca.asp` and supplied coordinates match the rule's described activity.                                           |
| ET INFO NetSupport Remote Admin Response                             | True positive for observed response                              | A response from `194.180.191.64:443` to the client session supports bidirectional communication.                                                                      |

Several alerts refer to the same packets or flow and are overlapping detections, not separate incidents. This table covers the alerts transcribed into the investigation notes; any additional alerts in the original alert archive should be reviewed before calling the alert review exhaustive.

## Indicators of Compromise (IOCs)

|Type|Indicator|Context / Confidence|
|---|---|---|
|IPv4|`194.180.191[.]64`|High-confidence suspicious NetSupport-like HTTP C2 endpoint.|
|URL|`hxxp://194.180.191[.]64/fakeurl.htm`|Repeated HTTP POST requests carrying NetSupport-like command fields.|
|Domain|`modandcrackedapk[.]com`|Suspicious domain observed in DNS and TLS SNI; malicious payload not identified.|
|IPv4|`193.42.38[.]139`|Destination IP of the TLS session with SNI `modandcrackedapk.com`.|
|Internal host|`10.11.26.183`|Affected host exhibiting the suspicious activity; not an external block IOC.|
|Hostname|`DESKTOP-B8TQK49`|Hostname associated with the affected endpoint.|

### Supporting Network Artifacts (not standalone malicious IOCs)

|Type|Artifact|Context|
|---|---|---|
|HTTP User-Agent|`NetSupport Manager/1.3`|Seen in requests to `194.180.191[.]64`.|
|HTTP Server header|`NetSupport Gateway/1.8 (Windows NT)`|Seen in responses from the external endpoint.|
|HTTP fields|`CMD=POLL`, `INFO=1`, `ACK=1`, `CMD=ENCD`, `ES=1`, `DATA=...`|Observed in the NetSupport-like request/response pattern; DATA contents were not decoded.|
|URL|`hxxp://geo.netsupportsoftware[.]com/location/loca.asp`|NetSupport geolocation lookup; treated as supporting context, not a malicious IOC.|
|Internal host|`10.11.26.3` (`NEMOTODES-DC`)|Domain controller involved in SMB/SAMR/MS-EFSR activity.|

No malware binary hash was established from the reviewed notes, so no SHA-256 file hash is claimed in this report.

## Limitations

- The PCAP and notes do not establish the initial-access vector. Phishing, a malicious download, or another delivery mechanism must not be asserted without additional evidence.
- The responsible process and any executable responsible for the network connections were not identified from the reviewed evidence.
- No direct evidence of data exfiltration was established. The opaque `DATA` field alone is not proof of exfiltration.
- The encrypted TLS payload for `modandcrackedapk.com` could not be inspected; the actual content and purpose of that session remain unknown.
- The SMBv1, NTLMSSP/ASN.1, SMB transaction, and MS-EFSR alerts do not prove successful exploitation, forced authentication, or denial of service.
- The interactive Windows user of the affected endpoint was not conclusively identified. `Administrator@NEMOTODES` was recorded in a later SMB context, not verified as the logged-on user.
- No malware file hash was available from the reviewed notes.
- Alert labels can overlap the same packets or flow. The table does not claim complete coverage of alerts that were not transcribed into the working notes.
- A discrepancy exists between the TLS 1.0 alert and the analyst's note recording TLS 1.2 for the Microsoft licensing connection; exact negotiated version remains to be verified.

## Verdict

**Assessment:** High-confidence suspicious NetSupport-like C2 activity from `10.11.26.183`; likely malicious or unauthorized use of NetSupport remote-access software.

**Confidence:** High for the NetSupport-like HTTP C2 pattern. Initial access, exact process execution, SMB/EFSR exploitation, and exfiltration remain unconfirmed.

### Reasoning

The strongest finding is the repeated HTTP POST traffic to `194.180.191.64:443/fakeurl.htm`, with the User-Agent `NetSupport Manager/1.3`, the response header `NetSupport Gateway/1.8 (Windows NT)`, NetSupport-style command fields, and multiple corroborating IDS alerts. Public reporting describes malicious NetSupport Manager abuse using HTTP POST requests to `fakeurl.htm` and a similar User-Agent. This is strong behavioral correlation, not proof of actor attribution or the initial-access method.

The separate TLS activity involving `modandcrackedapk.com` is suspicious but opaque. SMB/SAMR/MS-EFSR events are recorded as investigative leads, not confirmed exploitation. No conclusion of data exfiltration is supported by the reviewed evidence.

## Recommendations

1. In a live incident, isolate the affected host and preserve the PCAP, IDS alerts, endpoint telemetry, and relevant domain-controller logs.
2. Search DNS, proxy, firewall, NDR, and EDR records for `194.180.191[.]64`, `/fakeurl.htm`, `NetSupport Manager/1.3`, and `modandcrackedapk[.]com` across other hosts.
3. Validate whether NetSupport Manager is authorized in the environment. If unauthorized, identify the installed binary, its path, hash, process lineage, persistence, and any remote sessions using endpoint evidence.
4. Investigate the `modandcrackedapk.com` TLS session using available proxy/EDR telemetry and threat-intelligence sources; do not infer a downloaded file from encrypted traffic alone.
5. Review domain-controller logs and the full SMB request/response sequence around MS-EFSR, SAMR, IPC$, and SMBv1 alerts. Confirm authentication outcomes and whether any anomalous operation succeeded.
6. Check the affected endpoint for persistence, secondary payloads, remote interactive activity, and credential-access evidence before selecting remediation actions.
7. If the indicators are confirmed malicious in the environment, block the external endpoint and suspicious domain through appropriate controls, with change management and allowlist checks to avoid disrupting legitimate services.

## MITRE ATT&CK

|Tactic|Technique|Description|Assessment|
|---|---|---|---|
|Command and Control|[T1071.001](https://attack.mitre.org/techniques/T1071/001/)|Web Protocols|Supported by repeated HTTP POST C2-like communication. The traffic was HTTP on TCP/443, not necessarily HTTPS.|
|Command and Control|[T1219](https://attack.mitre.org/techniques/T1219/)|Remote Access Software|Supported as a behavioral mapping because the traffic identifies NetSupport Manager and is flagged as malicious NetSupport RAT activity. Authorization and the exact endpoint binary are not independently verified.|
|Discovery|[T1087.002](https://attack.mitre.org/techniques/T1087/002/)|Domain Account Discovery|Potential only: SAMR operations queried domain and user/group information, but malicious intent is not established.|

No Initial Access or Exfiltration technique is assigned because the available network evidence does not establish either activity. The MS-EFSR and SMB alerts are not mapped to a successful exploitation technique without corroborating evidence.

## Threat Intelligence References

- [Darktrace — NetSupport RAT: How Legitimate Tools Are as Damaging as Malware](https://www.darktrace.com/blog/netsupport-rat-how-legitimate-tools-can-be-as-damaging-as-malware)
