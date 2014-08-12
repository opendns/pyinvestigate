pyinvestigate
=============

Python module to interface with the OpenDNS Investigate API

# Installation
`pyinvestigate` can be installed either with pip:
```sh
$ pip install investigate
```

or manually:
```sh
$ git clone https://github.com/dead10ck/pyinvestigate.git
$ cd pyinvestigate
$ ./setup.py install
```

# Basic Usage
To use, simply build an `Investigate` object with your Investigate API key,
which can be found [here](https://sgraph.opendns.com/tokens-view).

```python
>>> import investigate
>>> api_key = 'f29be9cc-f833-4a9a-b984-19dc4d5186ac'

# categorization and status
>>> inv = investigate.Investigate(key)
>>> inv.categorization('amazon.com')
{u'amazon.com': {u'status': 1, u'content_categories': [u'8'], u'security_categories': []}}

# categorization and status on a list of domains with labels
>>> domains = ['www.amazon.com', 'www.opendns.com', 'bibikun.ru']
>>> inv.categorization(domains, labels=True)
{u'www.opendns.com': {u'status': 1, u'content_categories': [], u'security_categories': []}, u'www.amazon.com': {u'status': 1, u'content_categories': [u'Ecommerce/Shopping'], u'security_categories': []}, u'bibikun.ru': {u'status': -1, u'content_categories': [], u'security_categories': [u'Malware']}}

# cooccurrences
>>> inv.cooccurrences('test.com')
{u'found': True, u'pfs2': [[u'artstudioworks.net', 0.09335579514372229], [u'greencompany.com', 0.09335579514372229], [u'discovermammoth.com', 0.09335579514372229], [u'pacificwood.net', 0.09335579514372229], [u'www.harry4moonshine.com', 0.09335579514372229], [u'piedmontbank.com', 0.06762387315391016], [u'visiblebanking.com', 0.057415065440662744], [u'agenpialadunia.forexsignaler.com', 0.0549989754684476], [u'attached2parenting.com', 0.05348786151107391], [u'f15ijp.com', 0.04177207224401986], [u'www.mammothforums.com', 0.035603499171633544], [u'yazilimsozluk.com', 0.030851688398938874], [u'm.mixcloud.com', 0.025642243122907794], [u'vdoop.com', 0.01809189221816008], [u'jajah.com', 0.014693120965801757], [u'www.banterrabank.com', 0.014203066065439056], [u'ifbyphone.com', 0.01271383467301864], [u'riggedpoker.host56.com', 0.009728822740707535], [u'biamar.com.br', 0.009295803936207648], [u'www.pdfpasswordremover.tk', 0.009270658956305402], [u'textyourexbackfreesite.blogspot.com', 0.008774333937027498], [u'invox.com', 0.00831533412729124], [u'www.greenhopefinearts.org', 0.007618836085561211], [u'redirect.subscribe.ru', 0.007201461975779442], [u'sciencerush.homestead.com', 0.0064524714293837685], [u'ringcentral.com', 0.006078364744157428], [u'www.savingsdaily.com', 0.005755849214175203], [u'www.greenhopeband.org', 0.005654408857823953], [u'corp.myezaccess.com', 0.005433811444538917]]}

# related domains
>>> inv.related("test.com")
{u'tb1': [[u't.co', 11.0], [u'opcaobrasil.com.br', 10.0], [u'analytics.twitter.com', 9.0], [u'fallbackmx.spamexperts.eu', 8.0], [u'mx.spamexperts.com', 8.0], [u'watson.microsoft.com', 8.0], [u'www.pedroconti.com', 8.0], [u'ent-shasta-rrs.symantec.com', 7.0], [u'lastmx.spamexperts.net', 7.0], [u'www.julianburford.nl', 7.0], [u'www.facebook.com', 7.0], [u'1.gravatar.com', 6.0], [u'hrbssr.hrblock.com', 6.0], [u'rum-collector.pingdom.net', 6.0], [u'sites.google.com', 6.0], [u'www.fontfabric.com', 6.0], [u'fonts.googleapis.com', 5.0], [u'checkip.dyndns.org', 5.0], [u'c.microsoft.com', 5.0], [u'twitter.com', 5.0], [u'themenectar.ticksy.com', 5.0], [u'oauth.googleusercontent.com', 5.0], [u'homegroup.org.uk', 5.0], [u'google.com', 5.0], [u'fmr.hrblock.com', 4.0], [u'lifetouch.com', 4.0], [u'myblock.hrblock.com', 4.0], [u'ocsp.msocsp.com', 4.0], [u'ps.wcpss.net', 4.0], [u'spaceboundthemovie.tumblr.com', 4.0], [u'themes.googleusercontent.com', 4.0], [u'www.flickr.com', 4.0], [u'www.greetz.com', 4.0], [u'www.microsoft.com', 4.0], [u'www.twitter.com', 4.0], [u'0.gravatar.com', 3.0], [u'ak.fbcdn.net', 3.0], [u'assets.pinterest.com', 3.0], [u'business.telecomitalia.it', 3.0], [u'cdp1.public-trust.com', 3.0], [u'ctldl.windowsupdate.com', 3.0], [u'jajah.com', 3.0], [u'linkedin.com', 3.0], [u'ieonline.microsoft.com', 3.0], [u'ifbyphone.com', 3.0], [u'fpdownload2.macromedia.com', 3.0], [u'hm.webtrends.com', 3.0], [u'invox.com', 3.0], [u'www.trichromium.com', 3.0], [u'www.surveymonkey.com', 3.0], [u'www.linkedin.com', 3.0], [u'www.bing.com', 3.0], [u'www.4shared.com', 3.0], [u'time.windows.com', 3.0], [u'themenectar.com', 3.0], [u'statse.webtrendslive.com', 3.0], [u'skype.com', 3.0], [u'sfintest.hrblock.net', 3.0], [u'ringcentral.com', 3.0], [u'redirect.disqus.com', 3.0], [u'php.net', 3.0], [u'phone.com', 3.0], [u'paystub.wcpss.net', 3.0], [u'osp.osmsinc.com', 3.0], [u'ocsp.verisign.com', 3.0], [u'mx.canal2jujuy.com', 3.0], [u'memfeta.com.sa', 3.0]], u'found': True}

# security features
>>> inv.security("test.com")
{u'found': True, u'handlings': {u'blocked': 0.4166666666666667, u'normal': 0.5833333333333334}, u'dga_score': 0.0, u'rip_score': 0.0, u'asn_score': -0.1196966534327165, u'securerank2': 75.30526815812449, u'popularity': 52.80364108101653, u'tld_geodiversity': [], u'attack': u'', u'geoscore': 0.0, u'ks_test': 0.0, u'pagerank': 29.357018, u'entropy': 1.5, u'prefix_score': -1.485459001114686, u'perplexity': 0.021424157236163657, u'geodiversity': [[u'US', 0.6666667], [u'IL', 0.33333334]], u'fastflux': False, u'threat_type': u'', u'geodiversity_normalized': [[u'IL', 0.9945923984947999], [u'US', 0.005407601505200155]]}

# domain tags
>>> inv.domain_tags('bibikun.ru')
[{u'category': u'Malware', u'url': None, u'period': {u'begin': u'2013-09-16', u'end': u'Current'}}]

# domain RR history
>>> inv.rr_history('bibikun.ru')
{u'features': {u'geo_distance_mean': 0.0, u'locations': [{u'lat': 59.89440155029297, u'lon': 30.26420021057129}], u'rips': 1, u'is_subdomain': False, u'ttls_mean': 86400.0, u'non_routable': False, u'ff_candidate': False, u'base_domain': u'bibikun.ru', u'ttls_min': 86400, u'prefixes': [u'46.161.41.0'], u'rips_stability': 1.0, u'ttls_max': 86400, u'ttls_stddev': 0.0, u'prefixes_count': 1, u'mail_exchanger': False, u'geo_distance_sum': 0.0, u'asns_count': 1, u'country_count': 1, u'ttls_median': 86400.0, u'age': 92, u'asns': [44050], u'div_rips': 1.0, u'cname': False, u'country_codes': [u'RU'], u'locations_count': 1}, u'rrs_tf': [{u'first_seen': u'2014-05-12', u'rrs': [{u'class': u'IN', u'type': u'A', u'name': u'bibikun.ru.', u'rr': u'46.161.41.43', u'ttl': 86400}], u'last_seen': u'2014-07-04'}]}

# IP RR history
>>> inv.rr_history('50.23.225.49')
...

# latest domains for an IP
>>> inv.latest_domains('46.161.41.43')
[u'7ltd.biz', u'co0s.ru', u't0link.in', u'p0st.at', u'1ooz.asia', u'brand-sales.ru', u'xn--80aabhmtlfcyd3a1a.xn--p1ai', u'1000apps.ru', u'soapstock.net']
```
