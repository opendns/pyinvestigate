pyinvestigate
=============

> Python module to interface with the [OpenDNS Investigate API](https://docs.opendns.com/developer/investigate-api/)

# Installation
`pyinvestigate` can be installed either with pip:
```sh
$ pip install investigate
```

or manually:
```sh
$ git clone https://github.com/opendns/pyinvestigate
$ cd pyinvestigate
$ ./setup.py install
```

# Basic Usage
To use, simply build an `Investigate` object with your Investigate API key,
which can be found [here](https://sgraph.opendns.com/tokens-view).

```python
>>> import investigate
>>> api_key = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'

# Categorization and Status
>>> inv = investigate.Investigate(api_key)
>>> inv.categorization('amazon.com')
{u'amazon.com': {u'status': 1, u'content_categories': [u'8'], u'security_categories': []}}

# Categorization and Status on a list of domains with labels
>>> domains = ['www.amazon.com', 'www.opendns.com', 'bibikun.ru']
>>> inv.categorization(domains, labels=True)
{u'www.opendns.com': {u'status': 1, u'content_categories': [], u'security_categories': []}, u'www.amazon.com': {u'status': 1, u'content_categories': [u'Ecommerce/Shopping'], u'security_categories': []}, u'bibikun.ru': {u'status': -1, u'content_categories': [], u'security_categories': [u'Malware']}}

# Co-occurrences
>>> inv.cooccurrences('test.com')
{u'found': True, u'pfs2': [[u'artstudioworks.net', 0.09335579514372229], [u'greencompany.com', 0.09335579514372229], [u'discovermammoth.com', 0.09335579514372229], [u'pacificwood.net', 0.09335579514372229], [u'www.harry4moonshine.com', 0.09335579514372229], [u'piedmontbank.com', 0.06762387315391016], [u'visiblebanking.com', 0.057415065440662744], [u'agenpialadunia.forexsignaler.com', 0.0549989754684476], [u'attached2parenting.com', 0.05348786151107391], [u'f15ijp.com', 0.04177207224401986], [u'www.mammothforums.com', 0.035603499171633544], [u'yazilimsozluk.com', 0.030851688398938874], [u'm.mixcloud.com', 0.025642243122907794], [u'vdoop.com', 0.01809189221816008], [u'jajah.com', 0.014693120965801757], [u'www.banterrabank.com', 0.014203066065439056], [u'ifbyphone.com', 0.01271383467301864], [u'riggedpoker.host56.com', 0.009728822740707535], [u'biamar.com.br', 0.009295803936207648], [u'www.pdfpasswordremover.tk', 0.009270658956305402], [u'textyourexbackfreesite.blogspot.com', 0.008774333937027498], [u'invox.com', 0.00831533412729124], [u'www.greenhopefinearts.org', 0.007618836085561211], [u'redirect.subscribe.ru', 0.007201461975779442], [u'sciencerush.homestead.com', 0.0064524714293837685], [u'ringcentral.com', 0.006078364744157428], [u'www.savingsdaily.com', 0.005755849214175203], [u'www.greenhopeband.org', 0.005654408857823953], [u'corp.myezaccess.com', 0.005433811444538917]]}

# Related Domains
>>> inv.related("test.com")
{u'tb1': [[u't.co', 11.0], [u'opcaobrasil.com.br', 10.0], [u'analytics.twitter.com', 9.0], [u'fallbackmx.spamexperts.eu', 8.0], [u'mx.spamexperts.com', 8.0], [u'watson.microsoft.com', 8.0], [u'www.pedroconti.com', 8.0], [u'ent-shasta-rrs.symantec.com', 7.0], [u'lastmx.spamexperts.net', 7.0], [u'www.julianburford.nl', 7.0], [u'www.facebook.com', 7.0], [u'1.gravatar.com', 6.0], [u'hrbssr.hrblock.com', 6.0], [u'rum-collector.pingdom.net', 6.0], [u'sites.google.com', 6.0], [u'www.fontfabric.com', 6.0], [u'fonts.googleapis.com', 5.0], [u'checkip.dyndns.org', 5.0], [u'c.microsoft.com', 5.0], [u'twitter.com', 5.0], [u'themenectar.ticksy.com', 5.0], [u'oauth.googleusercontent.com', 5.0], [u'homegroup.org.uk', 5.0], [u'google.com', 5.0], [u'fmr.hrblock.com', 4.0], [u'lifetouch.com', 4.0], [u'myblock.hrblock.com', 4.0], [u'ocsp.msocsp.com', 4.0], [u'ps.wcpss.net', 4.0], [u'spaceboundthemovie.tumblr.com', 4.0], [u'themes.googleusercontent.com', 4.0], [u'www.flickr.com', 4.0], [u'www.greetz.com', 4.0], [u'www.microsoft.com', 4.0], [u'www.twitter.com', 4.0], [u'0.gravatar.com', 3.0], [u'ak.fbcdn.net', 3.0], [u'assets.pinterest.com', 3.0], [u'business.telecomitalia.it', 3.0], [u'cdp1.public-trust.com', 3.0], [u'ctldl.windowsupdate.com', 3.0], [u'jajah.com', 3.0], [u'linkedin.com', 3.0], [u'ieonline.microsoft.com', 3.0], [u'ifbyphone.com', 3.0], [u'fpdownload2.macromedia.com', 3.0], [u'hm.webtrends.com', 3.0], [u'invox.com', 3.0], [u'www.trichromium.com', 3.0], [u'www.surveymonkey.com', 3.0], [u'www.linkedin.com', 3.0], [u'www.bing.com', 3.0], [u'www.4shared.com', 3.0], [u'time.windows.com', 3.0], [u'themenectar.com', 3.0], [u'statse.webtrendslive.com', 3.0], [u'skype.com', 3.0], [u'sfintest.hrblock.net', 3.0], [u'ringcentral.com', 3.0], [u'redirect.disqus.com', 3.0], [u'php.net', 3.0], [u'phone.com', 3.0], [u'paystub.wcpss.net', 3.0], [u'osp.osmsinc.com', 3.0], [u'ocsp.verisign.com', 3.0], [u'mx.canal2jujuy.com', 3.0], [u'memfeta.com.sa', 3.0]], u'found': True}

# Security Features
>>> inv.security("test.com")
{u'found': True, u'handlings': {u'blocked': 0.4166666666666667, u'normal': 0.5833333333333334}, u'dga_score': 0.0, u'rip_score': 0.0, u'asn_score': -0.1196966534327165, u'securerank2': 75.30526815812449, u'popularity': 52.80364108101653, u'tld_geodiversity': [], u'attack': u'', u'geoscore': 0.0, u'ks_test': 0.0, u'pagerank': 29.357018, u'entropy': 1.5, u'prefix_score': -1.485459001114686, u'perplexity': 0.021424157236163657, u'geodiversity': [[u'US', 0.6666667], [u'IL', 0.33333334]], u'fastflux': False, u'threat_type': u'', u'geodiversity_normalized': [[u'IL', 0.9945923984947999], [u'US', 0.005407601505200155]]}

# Domain Tags
>>> inv.domain_tags('bibikun.ru')
[{u'category': u'Malware', u'url': None, u'period': {u'begin': u'2013-09-16', u'end': u'Current'}}]

# Domain RR history
>>> inv.rr_history('bibikun.ru')
{u'features': {u'geo_distance_mean': 0.0, u'locations': [{u'lat': 59.89440155029297, u'lon': 30.26420021057129}], u'rips': 1, u'is_subdomain': False, u'ttls_mean': 86400.0, u'non_routable': False, u'ff_candidate': False, u'base_domain': u'bibikun.ru', u'ttls_min': 86400, u'prefixes': [u'46.161.41.0'], u'rips_stability': 1.0, u'ttls_max': 86400, u'ttls_stddev': 0.0, u'prefixes_count': 1, u'mail_exchanger': False, u'geo_distance_sum': 0.0, u'asns_count': 1, u'country_count': 1, u'ttls_median': 86400.0, u'age': 92, u'asns': [44050], u'div_rips': 1.0, u'cname': False, u'country_codes': [u'RU'], u'locations_count': 1}, u'rrs_tf': [{u'first_seen': u'2014-05-12', u'rrs': [{u'class': u'IN', u'type': u'A', u'name': u'bibikun.ru.', u'rr': u'46.161.41.43', u'ttl': 86400}], u'last_seen': u'2014-07-04'}]}

# IP RR history
>>> inv.rr_history('50.23.225.49')
{u'rrs': [{u'name': u'50.23.225.49', u'type': u'A', u'class': u'IN', u'rr': u'test.3dnsgeo.com.', u'ttl': 300}], u'features': {u'div_ld2_2': 1.0, u'div_ld2_1': 1.0, u'div_ld3': 1.0, u'div_ld2': 1.0, u'ld2_1_count': 1, u'ld2_count': 1, u'rr_count': 1, u'ld3_count': 1, u'ld2_2_count': 1}}

# Latest domains for an IP
>>> inv.latest_domains('46.161.41.43')
[u'7ltd.biz', u'co0s.ru', u't0link.in', u'p0st.at', u'1ooz.asia', u'brand-sales.ru', u'xn--80aabhmtlfcyd3a1a.xn--p1ai', u'1000apps.ru', u'soapstock.net']

# Domains registered to an email (either currently or in the past)
>>> inv.email_whois('test@example.com')
{u'test@example.com': {u'domains': [{u'current': True, u'domain': u'173731331131.info'}, {u'current': True, u'domain': u'287finchleyroad.com'}, {u'current': True, u'domain': u'aada888ddd.com'}, {u'current': True, u'domain': u'aastagingwsh.net'}, {u'current': True, u'domain': u'againandagaoms.com'}, {u'current': True, u'domain': u'alliswelldomains.com'}, {u'current': True, u'domain': u'balise-testing-2paso.com'}, {u'current': False, u'domain': u'bananasaur.com'}, {u'current': False, u'domain': u'beerbadger.com'}, {u'current': True, u'domain': u'bobcarson.net'}, {u'current': True, u'domain': u'chkingoxlogindomains.com'}, {u'current': False, u'domain': u'creativelatvia.com'}, {u'current': False, u'domain': u'criticalawesomeness.com'},
...

# WHOIS record history for a domain
>>> inv.domain_whois('opendns.com')
[{u'registrantFaxExt': u'', u'administrativeContactPostalCode': u'94105', u'zoneContactCity': u'', u'addresses': [u'410 townsend st. suite 250'], u'billingContactState': u'', u'technicalContactCountry': u'UNITED STATES', u'auditUpdatedDate': u'2014-02-16 08:00:00 UTC', u'technicalContactFax': u'', u'technicalContactTelephone': u'0014153443118', u'billingContactStreet': [], u'registrantFax': u'', u'technicalContactPostalCode': u'94105', u'registrantOrganization': u'OpenDNS', u'zoneContactPostalCode': u'', u'technicalContactState': u'California', u'registrantState': u'California', u'administrativeContactName': u'OpenDNS Hostmaster', u'billingContactFaxExt': u'',
...

# Domains associated with a nameserver
>>> inv.ns_whois('auth1.opendns.com')
{u'auth1.opendns.com': {u'domains': [{u'current': True, u'domain': u'1800go.net'}, {u'current': True, u'domain': u'302directmedia.com'}, {u'current': False, u'domain': u'abboveactive.com'}, {u'current': False, u'domain': u'absurdant.com'}, {u'current': True, u'domain': u'account-updateinfo.com'}, {u'current': True, u'domain': u'account-updateinfo.net'}, {u'current': True, u'domain': u'account-updateinfo.org'}, {u'current': False, u'domain': u'activeclassic.com'}, {u'current': False, u'domain': u'advisorswise.com'}, {u'current': True, u'domain': u'afasterinternet.net'}, {u'current': True, u'domain': u'afasterinternet.org'}, {u'current': False, u'domain': u'agedwindow.com'}, {u'current': True, u'domain': u'airmor.com'}, {u'current': True, u'domain': u'airmor.net'}, {u'current': True, u'domain': u'airmor.org'},
...

# Search newly observed domains by regex pattern
>>> import datetime
>>> inv.search('paypal.*', start=datetime.timedelta(days=1), limit=100, include_category=True)
{u'matches': [{u'securityCategories': None, u'firstSeenISO': u'2016-02-12T11:18:00.000Z', u'name': u'paypal.cgi-bin.resolvemerchant.webappmpphome.com', u'firstSeen': 1455275880000}

# Associated malware samples for a domain, IP, or URL
>>> inv.samples('sso.anbtr.com')
{u'limit': 10, u'moreDataAvailable': True, u'samples': [{u'behaviors': [], u'sha1': u'e108f3e9b42cad9ed0891647fc73008681af35f7', u'threatScore': 100, u'visible': True, u'lastSeen': 1456260237000, u'sha256': u'775bbca4c7f1f36b25a9326a0c3980a40b69e4ba78e77adff26346cd736195b1', u'avresults': [], u'firstSeen': 1456260237000, u'md5': u'ca9be8f1d8761e5babbe0d123059d70c'}, {u'magicType': u'PE32 executable (GUI) Intel 80386, for MS Windows', u'behaviors': [], u'sha1': u'be55561a09d0eb785520329c6db6481ff8649965', u'lastSeen': 1456247770000, u'threatScore': 100, u'visible': True, u'firstSeen': 1456247770000, u'sha256': u'9b136c7238e07093a9522fac95fb889ec2a52662754a1a70c5bbf905cbcbf89b', u'avresults': [{u'product': u'ClamAV', u'signature': u'Win.Virus.Sality'}, {u'product': u'ClamAV', u'signature': u'Trojan.Agent'}], u'md5': u'd13fdb148b0701aab3f5d80ed4fbebe8', u'size': 103140}, {u'magicType': u'PE32 executable (GUI) Intel 80386 (stripped to external PDB), for MS Windows', u'behaviors': [], u'sha1': u'e7e212aea8d4830dac187b849ef0b892
...

# Detailed sample information
>>> inv.sample('414e38ed0b5d507734361c2ba94f734252ca33b8259ca32334f32c4dba69b01c')
{u'magicType': u'PE32 executable (GUI) Intel 80386 (stripped to external PDB), for MS Windows', u'behaviors': [{u'category': [u'file', u'persistence'], u'hits': 8, u'severity': 60, u'tags': [u'executable', u'file', u'process', u'PE'], u'title': u'Process Modified an Executable File', u'confidence': 100, u'threat': 60, u'name': u'modified-executable'}, {u'category': [u'file'], u'hits': 5, u'severity': 60, u'tags': [u'executable', u'file', u'process', u'PE'], u'title': u'Process Created an Executable in a User Directory', u'confidence': 95, u'threat': 57, u'name': u'created-executable-in-user-dir'}, {u'category': [u'forensics'], u'hits': 4, u'severity': 50, u'tags': [u'file'], u'title': u'Artifact Flagged by Antivirus', u'confidence': 50, u'threat': 25, u'name': u'antivirus-flagged-artifact'},
...

# Artifacts associated with a sample
>>> inv.sample_artifacts('414e38ed0b5d507734361c2ba94f734252ca33b8259ca32334f32c4dba69b01c')
{u'artifacts': [{u'magicType': u'HTML document, ASCII text, with no line terminators', u'behaviors': [], u'direction': u'OUT', u'sha1': u'48d628027388ba84af265623c1434a70bffdc175', u'visible': False, u'lastSeen': 1460762759000, u'md5': u'd072cd602211a6b4a1eda968df36cdc1', u'sha256': u'083d15a07f8702e1216f5ec39ee1879d1459e307a6ee7ae223651fed856dae93', u'avresults': [], u'firstSeen': 1460762759000, u'size': 51}, {u'magicType': u'Windows SYSTEM.INI, ASCII text, with CRLF line terminators', u'behaviors': [], u'direction': u'OUT', u'sha1': u'18e022df15da640920fb1cbfc8731e59eef523e3', u'visible': False, u'lastSeen': 1460762759000, u'md5': u'51317c1315b1951143370d961c8ca170', u'sha256': u'e959dafaa5b5a0b92003c587bff5ba552fd54635cf6f294d92287121b2d8bb12', u'avresults': [], u'firstSeen': 1460762759000, u'size': 472},
...

# Networks connections of a sample
>>> inv.sample_connections('414e38ed0b5d507734361c2ba94f734252ca33b8259ca32334f32c4dba69b01c')
{u'connections': [{u'threatTypes': [], u'name': u'sso.anbtr.com', u'attacks': [], u'securityCategories': [u'Malware'], u'ips': [], u'lastSeen': 1460762759000, u'urls': [], u'type': u'HOST', u'firstSeen': 1460762759000}, {u'threatTypes': [], u'name': u'arimaexim.com', u'attacks': [], u'securityCategories': [u'Drive-by Downloads/Exploits'], u'ips': [], u'lastSeen': 1460762759000, u'urls': [], u'type': u'HOST', u'firstSeen': 1460762759000}, {u'threatTypes': [], u'name': u'ankara-cambalkon.net', u'attacks': [], u'securityCategories': [], u'ips': [], u'lastSeen': 1460762759000, u'urls': [], u'type': u'HOST', u'firstSeen': 1460762759000}, {u'threatTypes': [], u'name': u'businecessity.com', u'attacks': [], u'securityCategories': [], u'ips': [], u'lastSeen': 1460762759000, u'urls': [], u'type': u'HOST', u'firstSeen': 1460762759000},
...

#  Other samples associated with that sample
>>> inv.sample_samples('befb538f7ee0903bd2ef783107b46f75bb2294f7c9598ba901eff35173fef360')
{u'limit': 10, u'totalResults': 10, u'moreDataAvailable': True, u'samples': [{u'magicType': u'PE32 executable (GUI) Intel 80386, for MS Windows', u'behaviors': [], u'direction': u'IN', u'sha1': u'c5a36cb704d8598d6cd80f449bea13db070b1633', u'lastSeen': 1463524837000, u'threatScore': 95, u'visible': True, u'firstSeen': 1463524837000, u'sha256': u'cad8c19af7476f7bf1f2516fc694081f99e40e550cc9db87683b06ed84e9a1dc', u'avresults': [], u'md5': u'20ceea3841cef8505873c1c05088becd', u'size': 1056404}, {u'magicType': u'PE32 executable (GUI) Intel 80386, for MS Windows', u'behaviors': [], u'direction': u'IN', u'sha1': u'fbf5dbadb7d083c3f7c7a33c2c86fe2d15e312cb', u'lastSeen': 1463448118000, u'threatScore': 90, u'visible': True, u'firstSeen': 1463448118000, u'sha256': u'f4dbbebdfa4fd0c9a54331c5b0b85613b231237909137d5c2567267282ffbebb',
...

```
