import json
import re
import requests
import urlparse
import datetime, time

class Investigate(object):
    BASE_URL = 'https://investigate.api.opendns.com/'
    SUPPORTED_DNS_TYPES = [
        "A",
        "NS",
        "MX",
        "TXT",
        "CNAME",
    ]

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
            "tags":                 "domains/{}/latest_tags",
            "whois_email":          "whois/emails/{}",
            "whois_ns":             "whois/nameservers/{}",
            "whois_domain":         "whois/{}/history",
            "search":               "search/{}?start={}"
        }
        self._auth_header = {"Authorization": "Bearer " + self.api_key}

    def get(self, uri, params={}):
        '''A generic method to make GET requests to the OpenDNS Investigate API
        on the given URI.
        '''
        return requests.get(urlparse.urljoin(Investigate.BASE_URL, uri),
            params=params, headers=self._auth_header, proxies=self.proxies
        )

    def post(self, uri, params={}, data={}):
        '''A generic method to make POST requests to the OpenDNS Investigate API
        on the given URI.
        '''
        return requests.post(
            urlparse.urljoin(Investigate.BASE_URL, uri),
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
        uri = urlparse.urljoin(self._uris['categorization'], domain)
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

        For more detail, see https://sgraph.opendns.com/docs/api#categorization
        '''
        if type(domains) is str:
            return self._get_categorization(domains, labels)
        elif type(domains) is list:
            return self._post_categorization(domains, labels)
        else:
            raise Investigate.DOMAIN_ERR

    def cooccurrences(self, domain):
        '''Get the cooccurrences of the given domain.

        For details, see https://sgraph.opendns.com/docs/api#co-occurrences
        '''
        uri = self._uris["cooccurrences"].format(domain)
        return self.get_parse(uri)

    def related(self, domain):
        '''Get the related domains of the given domain.

        For details, see https://sgraph.opendns.com/docs/api#relatedDomains
        '''
        uri = self._uris["related"].format(domain)
        return self.get_parse(uri)

    def security(self, domain):
        '''Get the Security Information for the given domain.

        For details, see https://sgraph.opendns.com/docs/api#securityInfo
        '''
        uri = self._uris["security"].format(domain)
        return self.get_parse(uri)

    def domain_tags(self, domain):
        '''Get the domain tagging dates for the given domain.

        For details, see https://sgraph.opendns.com/docs/api#latest_tags
        '''
        uri = self._uris["tags"].format(domain)
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

        For details, see https://sgraph.opendns.com/docs/api#dnsrr_domain
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
        return [ val for d in resp_json for key, val in d.iteritems() if key == 'name' ]

    def domain_whois(self, domain):
        '''Gets whois information for a domain'''
        uri = self._uris["whois_domain"].format(domain)
        resp_json = self.get_parse(uri)
        return resp_json

    def ns_whois(self, nameservers):
        '''Gets the domains that have been registered with a nameserver or
        nameservers'''
        if not isinstance(nameservers, list):
            uri = self._uris["whois_ns"].format(nameservers)
            params = {}
        else:
            uri = self._uris["whois_ns"].format('')
            params = {'emailList' : ','.join(nameservers)}

        resp_json = self.get_parse(uri, params=params)
        return resp_json

    def email_whois(self, emails):
        '''Gets the domains that have been registered with a given email
        address
        '''
        if not isinstance(emails, list):
            uri = self._uris["whois_email"].format(emails)
            params = {}
        else:
            uri = self._uris["whois_email"].format('')
            params = {'emailList' : ','.join(emails)}

        resp_json = self.get_parse(uri, params=params)
        return resp_json

    def search(self, pattern, start=None, limit=None, include_category=None):
        '''Searches for domains that match a given pattern'''
        
        if start is None:
            start = datetime.timedelta(days=30)

        if isinstance(start, datetime.timedelta):
            start_arg = int(time.mktime((datetime.datetime.utcnow() - start).timetuple()) * 1000)
        elif isinstance(start, datetime.datetime):
            start_arg = int(time.mktime(start.timetuple()) * 1000)
        else:
            raise Investigate.SEARCH_ERR
        
        limit_arg = ""
        if limit is not None and isinstance(limit, int):
            limit_arg = "&limit={}".format(limit)

        include_category_arg = ""
        if include_category is not None and isinstance(include_category, bool):
            include_category_arg = "&includeCategory={}".format(str(include_category).lower())

        uri = self._uris['search'].format(pattern, start_arg) + limit_arg + include_category_arg

        print uri

        return self.get_parse(uri)



