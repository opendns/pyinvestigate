from pprint import pprint
import pytest

def assert_keys_in(json_obj, *keys):
    for key in keys:
        assert key in json_obj

def test_categorization(inv):
    keys = ['status', 'content_categories', 'security_categories']

    # Test get with a single domain
    domain = 'www.amazon.com'
    resp_json = inv.get_categorization(domain)

    assert_keys_in(resp_json, domain)
    assert_keys_in(resp_json[domain], *keys)

    # test post with several domains
    domains = ['www.amazon.com', 'www.opendns.com', 'bibikun.ru']
    resp_json = inv.get_categorization(domains)
    assert_keys_in(resp_json, *domains)
    for d in domains:
        assert_keys_in(resp_json[d], *keys)

    # giving the wrong kind of object raises an exception
    with pytest.raises(Exception):
        inv.get_categorization({"wrong": "type"})

def test_cooccurrences(inv):
    resp_json = inv.get_cooccurrences('test.com')
    assert_keys_in(resp_json, 'found', 'pfs2')
    for double in resp_json['pfs2']:
        assert len(double) == 2
