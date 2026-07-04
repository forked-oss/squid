# Application Security Review Findings

Repository: [squid](https://github.com/forked-oss/squid)

Total active findings: 11

## Heap buffer overflow when appending DNS search path in idnsALookup

**Severity:** high

**Location:** src/dns_internal.cc

**Attacker:** Remote HTTP client whose request triggers DNS resolution

**Controlled input:** Hostname up to NS_MAXDNAME bytes with fewer than ndots label separators

**Attack path:** idnsALookup copies a max-length name into q->name then strcat appends search domain without bounds check

**Impact:** Heap corruption in Squid worker; potential RCE or DoS

## Cache Manager reflects attacker-controlled Origin with credentialed CORS letting malicious sites read localhost-reachable manager reports

**Severity:** high

**Location:** src/cache_manager.cc

**Attacker:** Remote website operator whose page is visited by a user whose browser can reach Squid cache manager on localhost

**Controlled input:** HTTP Origin header on cache-manager requests

**Attack path:** PutCommonResponseHeaders echoes Origin into Access-Control-Allow-Origin with Access-Control-Allow-Credentials true; default ACL allows localhost manager access

**Impact:** Exfiltration of sensitive operational data including live URLs, authenticated usernames, and connection metadata without cachemgr password on many actions

## Cache Manager config dump emits WCCP passwords and cache-peer login credentials in cleartext

**Severity:** medium

**Location:** src/wccp2.cc

**Attacker:** Party who can obtain config cache-manager report via password or credentialed CORS theft

**Controlled input:** Access to /squid-internal-mgr/config manager action

**Attack path:** dump_wccp2_service prints WCCP shared secret verbatim; dump_peer_options prints login= values while other secrets are masked

**Impact:** Disclosure of WCCP MD5 key and upstream peer credentials enabling cluster impersonation or authenticated relay

## Reflected XSS in URN resolution page with unescaped URN URL and resolver-supplied URLs in generated HTML

**Severity:** medium

**Location:** src/urn.cc

**Attacker:** Proxy client crafting URN request URL or attacker controlling URN resolver response

**Controlled input:** URN URL in client request and URLs returned by external URN resolver

**Attack path:** urnHandleReply interpolates e->url and resolver u->url into HTML without html_quote

**Impact:** JavaScript execution in browsers of users whose traffic passes through affected Squid instance

## FTP directory listing XSS via unescaped fallback LIST lines

**Severity:** medium

**Location:** src/clients/FtpGateway.cc

**Attacker:** Malicious FTP server operator or MITM of FTP data channel

**Controlled input:** FTP LIST line that fails ftpListParseParts parsing containing HTML or JavaScript

**Attack path:** htmlifyListEntry emits raw line without escaping in !parts fallback branch; listing HTML inserted into ERR_DIR_LISTING template without quoting

**Impact:** XSS against users browsing FTP via Squid; session hijack of proxy admin UI

## TLS AIA certificate-fetch SSRF via attacker-controlled caIssuers URI

**Severity:** medium

**Location:** src/ssl/support.cc

**Attacker:** Remote client triggering HTTPS origin connections where Squid validates TLS chains

**Controlled input:** caIssuers URI in upstream server X.509 Authority Info Access extension

**Attack path:** PeerConnector handleMissingCertificates collects AIA URIs via findIssuerUri and Downloader fetches them with no private-IP or metadata URL blocking

**Impact:** Blind SSRF from Squid process to internal services and cloud metadata during TLS chain validation

## LDAP DN injection in basic_ldap_auth direct-bind mode

**Severity:** high

**Location:** src/auth/basic/LDAP/basic_ldap_auth.cc

**Attacker:** Unauthenticated HTTP client using Basic auth against Squid when basic_ldap_auth runs without searchfilter direct-bind mode

**Controlled input:** Username with URL-encoded LDAP metacharacters such as victim%2Cou%3Dadmins

**Attack path:** Squid URL-decodes username; validUsername does not reject commas or equals; direct-bind snprintf builds uid=userid,basedn without escaping so injected commas change bind DN and ldap_simple_bind_s authenticates attacker-selected entry

**Impact:** Authentication bypass allowing login as arbitrary LDAP accounts when attacker knows credentials for different DN subtree

## Unauthenticated cachemgr cache enumeration leaks all cached objects

**Severity:** medium

**Location:** src/stat.cc

**Attacker:** Remote client reaching cache manager URLs when http_access permits manager access

**Controlled input:** GET /squid-internal-mgr/objects vm_objects or openfd_objects without password

**Attack path:** objects vm_objects and openfd_objects actions register with Protected::no so CheckPassword returns success when no cachemgr_passwd entry exists dumping full store contents

**Impact:** Enumeration of cached URLs metadata and sensitive cached response content

## FTP error-page percent-g embeds server-controlled listing without HTML escaping

**Severity:** medium

**Location:** src/errorpage.cc

**Attacker:** Malicious FTP server operator serving proxied FTP traffic

**Controlled input:** FTP directory listing containing HTML or JavaScript in listing bytes

**Attack path:** errorpage case g appends ftp.listing raw with do_quote=0 into text/html error pages without html_quote

**Impact:** Reflected XSS in Squid error-page origin enabling session theft against proxy users

## URN resolution open redirect via attacker-controlled Location header

**Severity:** medium

**Location:** src/urn.cc

**Attacker:** Any client allowed to send urn requests through the proxy

**Controlled input:** URLs in URN resolver response body selected as lowest-RTT target

**Attack path:** urnFindMinRtt selects attacker URL and urnHandleReply returns 302 with Location set without allowlist validation

**Impact:** Open redirect and phishing against proxy users

## URN resolution triggers ICMP probes to resolver-supplied internal hosts

**Severity:** medium

**Location:** src/urn.cc

**Attacker:** Any client allowed to send urn requests through the proxy

**Controlled input:** Hostnames in URN resolver response lines

**Attack path:** urnParseReply calls netdbPingSite for zero-RTT hosts causing Squid to ICMP-probe attacker-supplied internal hostnames

**Impact:** Blind internal-network reconnaissance from Squid network position
