from pprint import pprint
import pytest
import datetime

def assert_keys_in(json_obj, *keys):
    for key in keys:
        assert key in json_obj

def test_categorization(inv):
    keys = ['status', 'content_categories', 'security_categories']

    # Test get with a single domain
    domain = 'www.amazon.com'
    resp_json = inv.categorization(domain)

    assert_keys_in(resp_json, domain)
    assert_keys_in(resp_json[domain], *keys)

    # test post with several domains
    domains = ['www.amazon.com', 'www.umbrella.com', 'bibikun.ru']
    resp_json = inv.categorization(domains)
    assert_keys_in(resp_json, *domains)
    for d in domains:
        assert_keys_in(resp_json[d], *keys)

    # giving the wrong kind of object raises an exception
    with pytest.raises(Exception):
        inv.get_categorization({"wrong": "type"})

def test_cooccurrences(inv):
    resp_json = inv.cooccurrences('test.com')
    assert_keys_in(resp_json, 'found', 'pfs2')
    for double in resp_json['pfs2']:
        assert len(double) == 2

def test_related(inv):
    resp_json = inv.related("test.com")
    assert_keys_in(resp_json, 'found', 'tb1')
    for double in resp_json['tb1']:
        assert len(double) == 2

def test_security(inv):
    keys = [
        "dga_score",
        "perplexity",
        "entropy",
        "securerank2",
        "pagerank",
        "asn_score",
        "prefix_score",
        "rip_score",
        "popularity",
        "fastflux",
        "geodiversity",
        "geodiversity_normalized",
        "tld_geodiversity",
        "geoscore",
        "ks_test",
        "attack",
        "threat_type",
        "found"
    ]
    resp_json = inv.security("test.com")
    assert_keys_in(resp_json, *keys)

def test_domain_rr_history(inv):
    features_keys = [
        "age", "ttls_min", "ttls_max", "ttls_mean", "ttls_median", "ttls_stddev",
        "country_codes", "country_count", "asns", "asns_count", "rips_diversity",
        "locations", "locations_count", "geo_distance_sum", "geo_distance_mean",
        "non_routable", "mail_exchanger", "cname", "ff_candidate", "rips_stability",
        "prefixes", "prefixes_count",
        # undocumented results
        "rips", "is_subdomain", "base_domain", "div_rips"
    ]
    rrs_tf_keys = [
        "first_seen", "last_seen", "rrs"
    ]
    rrs_keys = [
        "name", "ttl", "class", "type", "rr"
    ]

    # test a domain
    resp_json = inv.rr_history('bibikun.ru')
    assert_keys_in(resp_json, 'features', 'rrs_tf')
    # make sure all the keys in the response are valid keys
    for key in resp_json['features'].keys():
        assert key in features_keys

    for rrs_tf_entry in resp_json['rrs_tf']:
        assert_keys_in(rrs_tf_entry, *rrs_tf_keys)
        for rr_entry in rrs_tf_entry['rrs']:
            assert_keys_in(rr_entry, *rrs_keys)

def test_ip_rr_history(inv):
    features_keys = [
        "rr_count", "ld2_count", "ld3_count", "ld2_1_count", "ld2_2_count",
        "div_ld2", "div_ld3", "div_ld2_1", "div_ld2_2"
    ]
    rr_keys = [
        "rr", "ttl", "class", "type", "name" # not 'ip' as the documentation says
    ]
    # test an IP
    resp_json = inv.rr_history('50.23.225.49')
    assert_keys_in(resp_json, 'rrs', 'features')
    assert_keys_in(resp_json['features'], *features_keys)
    for rr_entry in resp_json['rrs']:
        assert_keys_in(rr_entry, *rr_keys)

def test_latest_domains(inv):
    resp_json = inv.latest_domains('8.8.8.8')
    print("\nresp_json")
    pprint(resp_json)
    assert type(resp_json) is list
    assert len(resp_json) > 0

def test_email_whois1(inv):
    resp_json = inv.email_whois('test@example.com')
    print("\nresp_json")
    pprint(resp_json)
    whois_keys = ["domains", "limit", "moreDataAvailable", "totalResults", "offset"]
    assert_keys_in(resp_json, 'test@example.com')
    assert_keys_in(resp_json['test@example.com'], *whois_keys)

def test_email_whois2(inv):
    resp_json = inv.email_whois('admin@google.com', limit=10, offset=500)
    print("\nresp_json")
    pprint(resp_json)
    whois_keys = ["domains", "limit", "moreDataAvailable", "totalResults", "offset"]
    assert_keys_in(resp_json, 'admin@google.com')
    assert_keys_in(resp_json['admin@google.com'], *whois_keys)

def test_email_whois_sort_by_updated(inv):
    resp_json = inv.email_whois('admin@google.com', limit=10, sort_field='updated')
    print("\nresp_json")
    pprint(resp_json)
    whois_keys = ["domains", "limit", "moreDataAvailable", "totalResults", "offset"]
    assert_keys_in(resp_json, 'admin@google.com')
    assert resp_json['admin@google.com']['sortField'] == 'updated'

def test_email_whois_sort_by_created(inv):
    resp_json = inv.email_whois('admin@google.com', limit=10, sort_field='created')
    print("\nresp_json")
    pprint(resp_json)
    whois_keys = ["domains", "limit", "moreDataAvailable", "totalResults", "offset"]
    assert_keys_in(resp_json, 'admin@google.com')
    assert resp_json['admin@google.com']['sortField'] == 'created'

def test_email_whois_sort_by_expires(inv):
    resp_json = inv.email_whois('admin@google.com', limit=10, sort_field='expires')
    print("\nresp_json")
    pprint(resp_json)
    whois_keys = ["domains", "limit", "moreDataAvailable", "totalResults", "offset"]
    assert_keys_in(resp_json, 'admin@google.com')
    assert resp_json['admin@google.com']['sortField'] == 'expires'

def test_email_whois_sort_by_default(inv):
    resp_json = inv.email_whois('admin@google.com', limit=10)
    print("\nresp_json")
    pprint(resp_json)
    whois_keys = ["domains", "limit", "moreDataAvailable", "totalResults", "offset"]
    assert_keys_in(resp_json, 'admin@google.com')
    assert resp_json['admin@google.com']['sortField'] == 'domain name [default]'

def test_domain_whois(inv):
    resp_json = inv.domain_whois('umbrella.com')
    whois_keys = [
        'registrantFaxExt',
        'administrativeContactPostalCode',
        'zoneContactCity',
        'addresses',
        'billingContactState',
        'technicalContactCountry',
        'auditUpdatedDate',
        'technicalContactFax',
        'technicalContactTelephone',
        'billingContactStreet',
        'registrantFax',
        'technicalContactPostalCode',
        'registrantOrganization',
        'zoneContactPostalCode',
        'technicalContactState',
        'registrantState',
        'administrativeContactName',
        'billingContactFaxExt',
        'billingContactCity',
        'technicalContactEmail',
        'registrantCountry',
        'technicalContactFaxExt',
        'registrantName',
        'administrativeContactOrganization',
        'billingContactCountry',
        'billingContactName',
        'registrarName',
        'technicalContactTelephoneExt',
        'administrativeContactFaxExt',
        'zoneContactFax',
        'timestamp',
        'registrantCity',
        'zoneContactTelephoneExt',
        'administrativeContactTelephoneExt',
        'status',
        'updated',
        'whoisServers',
        'technicalContactName',
        'technicalContactStreet',
        'nameServers',
        'zoneContactFaxExt',
        'expires',
        'technicalContactCity',
        'administrativeContactStreet',
        'billingContactFax',
        'technicalContactOrganization',
        'administrativeContactState',
        'zoneContactOrganization',
        'billingContactPostalCode',
        'zoneContactStreet',
        'zoneContactName',
        'registrantPostalCode',
        'billingContactTelephone',
        'emails',
        'registrantTelephone',
        'administrativeContactCountry',
        'administrativeContactCity',
        'administrativeContactTelephone',
        'created',
        'registrantStreet',
        'domainName',
        'administrativeContactEmail',
        'billingContactEmail',
        'timeOfLatestRealtimeCheck',
        'zoneContactState',
        'registrantEmail',
        'administrativeContactFax',
        'billingContactTelephoneExt',
        'zoneContactCountry',
        'zoneContactEmail',
        'registrantTelephoneExt',
        'billingContactOrganization',
        'registrarIANAID',
        'zoneContactTelephone',
        'hasRawText']
    assert_keys_in(resp_json, *whois_keys)

def test_domain_whois_history(inv):
    resp_json = inv.domain_whois_history('test.com', 5)
    assert len(resp_json) > 0

def test_ns_whois(inv):
    resp_json = inv.ns_whois('auth1.umbrella.com')
    assert_keys_in(resp_json, 'auth1.umbrella.com')
    whois_keys = ["domains", "limit", "moreDataAvailable", "totalResults", "offset"]
    assert_keys_in(resp_json['auth1.umbrella.com'], *whois_keys)

def test_ns_whois_sort_by_created(inv):
    resp_json = inv.ns_whois('auth1.umbrella.com', sort_field='created')
    assert_keys_in(resp_json, 'auth1.umbrella.com')
    assert resp_json['auth1.umbrella.com']['sortField'] == 'created'

def test_ns_whois_sort_by_updated(inv):
    resp_json = inv.ns_whois('auth1.umbrella.com', sort_field='updated')
    assert_keys_in(resp_json, 'auth1.umbrella.com')
    assert resp_json['auth1.umbrella.com']['sortField'] == 'updated'

def test_ns_whois_sort_by_expires(inv):
    resp_json = inv.ns_whois('auth1.umbrella.com', sort_field='expires')
    assert_keys_in(resp_json, 'auth1.umbrella.com')
    assert resp_json['auth1.umbrella.com']['sortField'] == 'expires'

def test_ns_whois_sort_by_default(inv):
    resp_json = inv.ns_whois('auth1.umbrella.com')
    assert_keys_in(resp_json, 'auth1.umbrella.com')
    assert resp_json['auth1.umbrella.com']['sortField'] == 'domain name [default]'

def test_search(inv):
    resp_json = inv.search('paypal.*', start=datetime.timedelta(days=1), limit=100, include_category=True, _type='all')

    search_keys = [
        'matches', 'totalResults', 'limit', 'expression', 'moreDataAvailable'
    ]

    match_keys = [
        'securityCategories', 'firstSeenISO', 'name', 'firstSeen'
    ]

    assert_keys_in(resp_json, *search_keys)
    assert_keys_in(resp_json['matches'][0], *match_keys)

def test_samples(inv):
    resp_json = inv.samples('sso.anbtr.com')

    search_keys = [
        'query',
        'totalResults',
        'moreDataAvailable',
        'limit',
        'offset',
        'samples'
    ]

    samples_keys = [
        'sha256',
        'sha1',
        'md5',
        'threatScore',
        'firstSeen',
        'lastSeen',
        'visible',
        'avresults',
        'behaviors'
    ]

    assert_keys_in(resp_json, *search_keys)
    assert_keys_in(resp_json['samples'][0], *samples_keys)

def test_sample(inv):
    resp_json = inv.sample('414e38ed0b5d507734361c2ba94f734252ca33b8259ca32334f32c4dba69b01c')

    samples_keys = [
        'sha256',
        'sha1',
        'md5',
        'magicType',
        'threatScore',
        'size',
        'firstSeen',
        'lastSeen',
        'visible',
        'avresults',
        'samples',
        'connections',
        'behaviors'
    ]

    assert_keys_in(resp_json, *samples_keys)

def test_sample_artifacts(inv):
    resp_json = inv.sample_artifacts('414e38ed0b5d507734361c2ba94f734252ca33b8259ca32334f32c4dba69b01c')

    search_keys = [
        'totalResults',
        'moreDataAvailable',
        'limit',
        'offset',
        'artifacts'
    ]

    artifacts_keys = [
        'sha256',
        'sha1',
        'md5',
        'size',
        'firstSeen',
        'lastSeen',
        'visible',
        'direction',
        'avresults',
        'behaviors'
    ]

    assert_keys_in(resp_json, *search_keys)
    assert_keys_in(resp_json['artifacts'][0], *artifacts_keys)

def test_sample_connections(inv):
    resp_json = inv.sample_connections('414e38ed0b5d507734361c2ba94f734252ca33b8259ca32334f32c4dba69b01c')

    search_keys = [
        'totalResults',
        'moreDataAvailable',
        'limit',
        'offset',
        'connections'
    ]

    connections_keys = [
        'name',
        'firstSeen',
        'lastSeen',
        'securityCategories',
        'attacks',
        'threatTypes',
        'type',
        'ips',
        'urls'
    ]

    assert_keys_in(resp_json, *search_keys)
    assert_keys_in(resp_json['connections'][0], *connections_keys)

def test_sample_samples(inv):
    resp_json = inv.sample_samples('befb538f7ee0903bd2ef783107b46f75bb2294f7c9598ba901eff35173fef360')

    search_keys = [
        'totalResults',
        'moreDataAvailable',
        'limit',
        'offset',
        'samples'
    ]

    samples_keys = [
        'sha256',
        'sha1',
        'md5',
        'magicType',
        'threatScore',
        'size',
        'firstSeen',
        'lastSeen',
        'visible',
        'direction',
        'avresults',
        'behaviors'
    ]

    assert_keys_in(resp_json, *search_keys)
    assert_keys_in(resp_json['samples'][0], *samples_keys)

def test_as_for_ip(inv):
    resp_json = inv.as_for_ip('208.67.222.222')

    search_keys = [
        'cidr',
        'asn',
        'ir',
        'description',
        'creation_date'
    ]

    assert_keys_in(resp_json[0], *search_keys)

def test_prefixes_for_asn(inv):
    resp_json = inv.prefixes_for_asn(36692)

    search_keys = [
        'cidr',
        'geo'
    ]

    geo_keys = [
        'country_name',
        'country_code'
    ]

    assert_keys_in(resp_json[0], *search_keys)
    assert_keys_in(resp_json[0]['geo'], *geo_keys)

def test_timeline(inv):
    resp_json = inv.timeline('internetbadguys.com')

    search_keys = [
        'categories',
        'attacks',
        'threatTypes',
        'timestamp'
    ]

    assert_keys_in(resp_json[0], *search_keys)

def test_pdns_domain(inv):
    resp_json = inv.pdns_domain('coinhive.com')

    search_keys = [
        'records',
        'pageInfo',
        'recordInfo'
    ]

    records_keys = [
        'minTtl',
        'maxTtl',
        'firstSeen',
        'lastSeen',
        'name',
        'type',
        'rr',
        'securityCategories',
        'contentCategories',
        'firstSeenISO',
        'lastSeenISO'
    ]

    pageInfo_keys = [
        'hasMoreRecords',
        'offset',
        'limit',
        'totalNumRecords'
    ]
    assert_keys_in(resp_json, *search_keys)
    assert_keys_in(resp_json['records'][0], *records_keys)
    assert_keys_in(resp_json['pageInfo'], *pageInfo_keys)

def test_pdns_name(inv):
    resp_json = inv.pdns_name('coinhive.com')

    search_keys = [
        'records',
        'pageInfo',
        'recordInfo'
    ]

    records_keys = [
        'minTtl',
        'maxTtl',
        'firstSeen',
        'lastSeen',
        'name',
        'type',
        'rr',
        'securityCategories',
        'contentCategories',
        'firstSeenISO',
        'lastSeenISO'
    ]

    pageInfo_keys = [
        'hasMoreRecords',
        'offset',
        'limit',
        'totalNumRecords'
    ]

    assert_keys_in(resp_json, *search_keys)
    assert_keys_in(resp_json['pageInfo'], *pageInfo_keys)
    assert_keys_in(resp_json['records'][0], *records_keys)

def test_pdns_ip(inv):
    resp_json = inv.pdns_ip('146.112.61.104')

    search_keys = [
        'records',
        'pageInfo',
        'recordInfo'
    ]

    records_keys = [
        'minTtl',
        'maxTtl',
        'firstSeen',
        'lastSeen',
        'name',
        'type',
        'rr',
        'securityCategories',
        'contentCategories',
        'firstSeenISO',
        'lastSeenISO'
    ]

    pageInfo_keys = [
        'hasMoreRecords',
        'offset',
        'limit',
        'totalNumRecords'
    ]

    assert_keys_in(resp_json, *search_keys)
    assert_keys_in(resp_json['pageInfo'], *pageInfo_keys)
    assert_keys_in(resp_json['records'][0], *records_keys)

def test_pdns_timeline(inv):
    resp_json = inv.pdns_timeline('umbrella.com')

    search_keys = [
        'date',
        'dnsData'
    ]

    assert_keys_in(resp_json[0], *search_keys)

def test_pdns_raw(inv):
    resp_json = inv.pdns_raw('google')

    search_keys = [
        'records',
        'pageInfo',
        'recordInfo'
    ]

    records_keys = [
        'minTtl',
        'maxTtl',
        'firstSeen',
        'lastSeen',
        'name',
        'type',
        'rr',
        'securityCategories',
        'contentCategories',
        'firstSeenISO',
        'lastSeenISO'
    ]

    pageInfo_keys = [
        'hasMoreRecords',
        'offset',
        'limit',
        'totalNumRecords'
    ]

    assert_keys_in(resp_json, *search_keys)
    assert_keys_in(resp_json['pageInfo'], *pageInfo_keys)
    assert_keys_in(resp_json['records'][0], *records_keys)

def test_domain_volume(inv):
    resp_json = inv.domain_volume('umbrella.com', start=datetime.timedelta(days=1), match='component')

    search_keys = [
        'dates',
        'queries',
    ]

    assert_keys_in(resp_json, *search_keys)

def test_risk_score(inv):
    resp_json = inv.risk_score('bibikun.ru')

    search_keys = [
        'risk_score'
    ]

    assert_keys_in(resp_json, *search_keys)
