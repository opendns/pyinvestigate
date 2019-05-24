from future.standard_library import install_aliases
install_aliases()

import json
import re
import requests
import datetime, time
from future.utils import iteritems
from urllib.parse import urljoin, quote_plus


class Investigate(object):
    BASE_URL = 'https://investigate.api.umbrella.com/'
    SUPPORTED_DNS_TYPES = [
        "A",
        "NS",
        "MX",
        "TXT",
        "CNAME",
    ]

    DEFAULT_LIMIT = None
    DEFAULT_OFFSET = None
    DEFAULT_SORT = None
    IP_PATTERN = re.compile(r'(\d{1,3}\.){3}\d{1,3}')

    DOMAIN_ERR = ValueError("domains must be a string or a list of strings")
    IP_ERR = ValueError("invalid IP address")
    UNSUPPORTED_DNS_QUERY = ValueError("supported query types are: {}"
        .format(SUPPORTED_DNS_TYPES)
    )
    SEARCH_ERR = ValueError("Start argument must be a datetime or a timedelta")

    def __init__(self, api_key, proxies={}):
        self.api_key = api_key
        self.proxies = proxies
        self._uris = {
            "categorization":       "domains/categorization/",
            "cooccurrences":        "recommendations/name/{}.json",
            "domain_rr_history":    "dnsdb/name/{}/{}.json",
            "ip_rr_history":        "dnsdb/ip/{}/{}.json",
            "latest_domains":       "ips/{}/latest_domains",
            "related":              "links/name/{}.json",
            "security":             "security/name/{}.json",
            "whois_email":          "whois/emails/{}",
            "whois_ns":             "whois/nameservers/{}",
            "whois_domain":         "whois/{}",
            "whois_domain_history": "whois/{}/history",
            "search":               "search/{}",
            "samples":              "samples/{}",
            "sample":               "sample/{}",
            "sample_artifacts":     "sample/{}/artifacts",
            "sample_connections":   "sample/{}/connections",
            "sample_samples":       "sample/{}/samples",
            "as_for_ip":            "bgp_routes/ip/{}/as_for_ip.json",
            "prefixes_for_asn":     "bgp_routes/asn/{}/prefixes_for_asn.json",
            "timeline":             "timeline/{}",
            "pdns_domain":          "pdns/domain/{}",
            "pdns_name":            "pdns/name/{}",
            "pdns_ip":              "pdns/ip/{}",
            "pdns_timeline":        "pdns/timeline/{}",
            "pdns_raw":             "pdns/raw/\"{}\"",
            "domain_volume":        "domains/volume/{}"
        }
        self._auth_header = {"Authorization": "Bearer " + self.api_key}
        self._session = requests.Session()

    def get(self, uri, params={}):
        '''A generic method to make GET requests to the OpenDNS Investigate API
        on the given URI.
        '''
        return self._session.get(urljoin(Investigate.BASE_URL, uri),
            params=params, headers=self._auth_header, proxies=self.proxies
        )

    def post(self, uri, params={}, data={}):
        '''A generic method to make POST requests to the OpenDNS Investigate API
        on the given URI.
        '''
        return self._session.post(
            urljoin(Investigate.BASE_URL, uri),
            params=params, data=data, headers=self._auth_header,
            proxies=self.proxies
        )

    def _request_parse(self, method, *args):
        r = method(*args)
        r.raise_for_status()
        return r.json()

    def get_parse(self, uri, params={}):
        '''Convenience method to call get() on an arbitrary URI and parse the response
        into a JSON object. Raises an error on non-200 response status.
        '''
        return self._request_parse(self.get, uri, params)

    def post_parse(self, uri, params={}, data={}):
        '''Convenience method to call post() on an arbitrary URI and parse the response
        into a JSON object. Raises an error on non-200 response status.
        '''
        return self._request_parse(self.post, uri, params, data)

    def _get_categorization(self, domain, labels):
        uri = urljoin(self._uris['categorization'], domain)
        params = {'showLabels': True} if labels else {}
        return self.get_parse(uri, params)

    def _post_categorization(self, domains, labels):
        params = {'showLabels': True} if labels else {}
        return self.post_parse(self._uris['categorization'], params,
            json.dumps(domains)
        )

    def categorization(self, domains, labels=False):
        '''Get the domain status and categorization of a domain or list of domains.
        'domains' can be either a single domain, or a list of domains.
        Setting 'labels' to True will give back categorizations in human-readable
        form.

        For more detail, see https://investigate.umbrella.com/docs/api#categorization
        '''
        if type(domains) is str:
            return self._get_categorization(domains, labels)
        elif type(domains) is list:
            return self._post_categorization(domains, labels)
        else:
            raise Investigate.DOMAIN_ERR

    def cooccurrences(self, domain):
        '''Get the cooccurrences of the given domain.

        For details, see https://investigate.umbrella.com/docs/api#co-occurrences
        '''
        uri = self._uris["cooccurrences"].format(domain)
        return self.get_parse(uri)

    def related(self, domain):
        '''Get the related domains of the given domain.

        For details, see https://investigate.umbrella.com/docs/api#relatedDomains
        '''
        uri = self._uris["related"].format(domain)
        return self.get_parse(uri)

    def security(self, domain):
        '''Get the Security Information for the given domain.

        For details, see https://investigate.umbrella.com/docs/api#securityInfo
        '''
        uri = self._uris["security"].format(domain)
        return self.get_parse(uri)

    def _domain_rr_history(self, domain, query_type):
        uri = self._uris["domain_rr_history"].format(query_type, domain)
        return self.get_parse(uri)

    def _ip_rr_history(self, ip, query_type):
        uri = self._uris["ip_rr_history"].format(query_type, ip)
        return self.get_parse(uri)

    def rr_history(self, query, query_type="A"):
        '''Get the RR (Resource Record) History of the given domain or IP.
        The default query type is for 'A' records, but the following query types
        are supported:

        A, NS, MX, TXT, CNAME

        For details, see https://investigate.umbrella.com/docs/api#dnsrr_domain
        '''
        if query_type not in Investigate.SUPPORTED_DNS_TYPES:
            raise Investigate.UNSUPPORTED_DNS_QUERY

        # if this is an IP address, query the IP
        if Investigate.IP_PATTERN.match(query):
            return self._ip_rr_history(query, query_type)

        # otherwise, query the domain
        return self._domain_rr_history(query, query_type)

    def latest_domains(self, ip):
        '''Gets the latest known malicious domains associated with the given
        IP address, if any. Returns the list of malicious domains.
        '''
        if not Investigate.IP_PATTERN.match(ip):
            raise Investigate.IP_ERR

        uri = self._uris["latest_domains"].format(ip)
        resp_json = self.get_parse(uri)

        # parse out the domain names
        return [ val for d in resp_json for key, val in iteritems(d) if key == 'name' ]

    def domain_whois(self, domain):
        '''Gets whois information for a domain'''
        uri = self._uris["whois_domain"].format(domain)
        resp_json = self.get_parse(uri)
        return resp_json

    def domain_whois_history(self, domain, limit=None):
        '''Gets whois history for a domain'''

        params = dict()
        if limit is not None:
            params['limit'] = limit

        uri = self._uris["whois_domain_history"].format(domain)
        resp_json = self.get_parse(uri, params)
        return resp_json

    def ns_whois(self, nameservers, limit=DEFAULT_LIMIT, offset=DEFAULT_OFFSET, sort_field=DEFAULT_SORT):
        '''Gets the domains that have been registered with a nameserver or
        nameservers'''
        if not isinstance(nameservers, list):
            uri = self._uris["whois_ns"].format(nameservers)
            params = {'limit': limit, 'offset': offset, 'sortField': sort_field}
        else:
            uri = self._uris["whois_ns"].format('')
            params = {'emailList' : ','.join(nameservers), 'limit': limit, 'offset': offset, 'sortField': sort_field}

        resp_json = self.get_parse(uri, params=params)
        return resp_json

    def email_whois(self, emails, limit=DEFAULT_LIMIT, offset=DEFAULT_OFFSET, sort_field=DEFAULT_SORT):
        '''Gets the domains that have been registered with a given email
        address
        '''
        if not isinstance(emails, list):
            uri = self._uris["whois_email"].format(emails)
            params = {'limit': limit, 'offset': offset, 'sortField': sort_field}
        else:
            uri = self._uris["whois_email"].format('')
            params = {'emailList' : ','.join(emails), 'limit': limit, 'offset': offset, 'sortField': sort_field}

        resp_json = self.get_parse(uri, params=params)
        return resp_json

    def search(self, pattern, start=None, limit=None, include_category=None):
        '''Searches for domains that match a given pattern'''

        params = dict()

        if start is None:
            start = datetime.timedelta(days=30)

        if isinstance(start, datetime.timedelta):
            params['start'] = int(time.mktime((datetime.datetime.utcnow() - start).timetuple()) * 1000)
        elif isinstance(start, datetime.datetime):
            params['start'] = int(time.mktime(start.timetuple()) * 1000)
        else:
            raise Investigate.SEARCH_ERR

        if limit is not None and isinstance(limit, int):
            params['limit'] = limit
        if include_category is not None and isinstance(include_category, bool):
            params['includeCategory'] = str(include_category).lower()

        uri = self._uris['search'].format(quote_plus(pattern))

        return self.get_parse(uri, params)

    def samples(self, anystring, limit=None, offset=None, sortby=None):
        '''Return an object representing the samples identified by the input domain, IP, or URL'''

        uri = self._uris['samples'].format(anystring)
        params = {'limit': limit, 'offset': offset, 'sortby': sortby}

        return self.get_parse(uri, params)

    def sample(self, hash, limit=None, offset=None):
        '''Return an object representing the sample identified by the input hash, or an empty object if that sample is not found'''

        uri = self._uris['sample'].format(hash)
        params = {'limit': limit, 'offset': offset}

        return self.get_parse(uri, params)

    def sample_artifacts(self, hash, limit=None, offset=None):
        '''
            Return an object representing artifacts associated with an input hash
            NOTE: Only available to Threat Grid customers
        '''

        uri = self._uris['sample_artifacts'].format(hash)
        params = {'limit': limit, 'offset': offset}

        return self.get_parse(uri, params)

    def sample_connections(self, hash, limit=None, offset=None):
        '''Return an object representing network connections associated with an input hash'''

        uri = self._uris['sample_connections'].format(hash)
        params = {'limit': limit, 'offset': offset}

        return self.get_parse(uri, params)

    def sample_samples(self, hash, limit=None, offset=None):
        '''Return an object representing samples associated with an input hash'''

        uri = self._uris['sample_samples'].format(hash)
        params = {'limit': limit, 'offset': offset}

        return self.get_parse(uri, params)

    def as_for_ip(self, ip):
        '''Gets the AS information for a given IP address.'''
        if not Investigate.IP_PATTERN.match(ip):
            raise Investigate.IP_ERR

        uri = self._uris["as_for_ip"].format(ip)
        resp_json = self.get_parse(uri)

        return resp_json

    def prefixes_for_asn(self, asn):
        '''Gets the AS information for a given ASN. Return the CIDR and geolocation associated with the AS.'''
        uri = self._uris["prefixes_for_asn"].format(asn)
        resp_json = self.get_parse(uri)

        return resp_json

    def timeline(self, uri):
        '''Get the domain tagging timeline for a given uri. 
        Could be a domain, ip, or url.
        For details, see https://docs.umbrella.com/investigate-api/docs/timeline
        '''
        uri = self._uris["timeline"].format(uri)
        resp_json = self.get_parse(uri)

        return resp_json


    def pdns_domain(self, domain, limit=None, offset=0, sortorder='desc', sortby=None, recordType=None):
        '''Returns the Resource Record(RR) data for DNS responses, and categorization data,
        where the answer ( or rdata) is the domain(s).
        '''
        uri = self._uris["pdns_domain"].format(domain)
        params = {'limit': limit, 'offset': offset, sortorder: sortorder, sortby: sortby, recordType: recordType}

        return self.get_parse(uri, params)

    def pdns_name(self, name, limit=None, offset=0, sortorder='desc', sortby=None, recordType=None):
        '''
        Returns data from DNS queries that resolvers received, and categorization data.
        '''
        uri = self._uris["pdns_name"].format(name)
        params = {'limit': limit, 'offset': offset, sortorder: sortorder, sortby: sortby, recordType: recordType}

        return self.get_parse(uri, params)

    def pdns_ip(self, ip, limit=None, offset=0, sortorder='desc', sortby=None, recordType=None):
        '''
        Returns the Resource Record (RR) data for DNS responses, and categorization data, where the answer (or data) is the IP address.
        '''
        uri = self._uris["pdns_ip"].format(ip)
        params = {'limit': limit, 'offset': offset, sortorder: sortorder, sortby: sortby, recordType: recordType}

        return self.get_parse(uri, params)

    def pdns_timeline(self, timeline, recordType=None):
        '''
        Get a snapshot of passive DNS and Umbrella categorization history for a domain name.
        '''
        uri = self._uris["pdns_timeline"].format(timeline)
        params = {recordType: recordType}

        return self.get_parse(uri, params)

    def pdns_raw(self, raw, limit=None, offset=0, sortorder='desc', sortby=None, recordType=None):
        '''
        Get passive DNS and Umbrella categorization data for TXT records.
        '''
        uri = self._uris["pdns_raw"].format(raw)
        params = {'limit': limit, 'offset': offset, sortorder: sortorder, sortby: sortby, recordType: recordType}

        return self.get_parse(uri, params)

    def domain_volume(self, domain, start=None, stop=None, match='all'):
        '''Number of DNS queries made per hour to the specified domain by users'''

        params = dict()

        if start is None:
            start = datetime.timedelta(days=30)
        if isinstance(start, datetime.timedelta):
            params['start'] = int(time.mktime((datetime.datetime.utcnow() - start).timetuple()) * 1000)
        elif isinstance(start, datetime.datetime):
            params['start'] = int(time.mktime(start.timetuple()) * 1000)
        else:
            raise Investigate.SEARCH_ERR

        if stop is None:
            stop = datetime.datetime.now()
        if isinstance(stop, datetime.timedelta):
            params['stop'] = int(time.mktime((datetime.datetime.utcnow() - stop).timetuple()) * 1000)
        elif isinstance(stop, datetime.datetime):
            params['stop'] = int(time.mktime(stop.timetuple()) * 1000)
        else:
            raise Investigate.SEARCH_ERR

        if match is not None and match in ('all' or 'component' or 'exact'):
            params['match'] = match

        uri = self._uris['domain_volume'].format(domain)

        return self.get_parse(uri, params)
