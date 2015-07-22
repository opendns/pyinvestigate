from pprint import pprint
import pytest

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
    domains = ['www.amazon.com', 'www.opendns.com', 'bibikun.ru']
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
        "fastflux",
        "popularity",
        "geodiversity",
        "geodiversity_normalized",
        "tld_geodiversity",
        "geoscore",
        "ks_test",
        "handlings",
        "attack",
        "threat_type",
        "found",
    ]
    resp_json = inv.security("test.com")
    assert_keys_in(resp_json, *keys)

def test_domain_tags(inv):
    resp_json = inv.domain_tags('bibikun.ru')
    for tag_entry in resp_json:
        assert_keys_in(tag_entry, 'category', 'period', 'url')
        assert_keys_in(tag_entry['period'], 'begin', 'end')

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
    resp_json = inv.latest_domains('46.161.41.43')
    print("\nresp_json")
    pprint(resp_json)
    assert type(resp_json) is list
    assert len(resp_json) > 0

def test_email_whois(inv):
    resp_json = inv.email_whois('test@example.com')
    print("\nresp_json")
    pprint(resp_json)
    whois_keys = ["domains", "limit", "moreDataAvailable", "totalResults"]
    assert_keys_in(resp_json, 'test@example.com')
    assert_keys_in(resp_json['test@example.com'], *whois_keys)

def test_domain_whois(inv):
    resp_json = inv.domain_whois('opendns.com')
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
    assert_keys_in(resp_json[0], *whois_keys)

def test_ns_whois(inv):
    resp_json = inv.ns_whois('auth1.opendns.com')
    assert_keys_in(resp_json, 'auth1.opendns.com')
    whois_keys = ["domains", "limit", "moreDataAvailable", "totalResults"]
    assert_keys_in(resp_json['auth1.opendns.com'], *whois_keys)

