import pytest
import requests

from prismsca import osv
from prismsca.inventory import Package


class FakeResp:
    def __init__(self, data, status=200):
        self._data, self.status_code = data, status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code}")

    def json(self):
        return self._data


class FakeSession:
    """Answers querybatch with `vulns_by_name` and /vulns/<id> with a stub record."""

    def __init__(self, vulns_by_name=None, fail=False):
        self.vulns_by_name = vulns_by_name or {}
        self.fail = fail
        self.posts = 0

    def post(self, url, json, timeout):
        self.posts += 1
        if self.fail:
            raise requests.ConnectionError("network down")
        assert url.endswith("/querybatch")
        return FakeResp(
            {"results": [{"vulns": [{"id": i} for i in self.vulns_by_name.get(q["package"]["name"], [])]} for q in json["queries"]]}
        )

    def get(self, url, timeout):
        vid = url.rsplit("/", 1)[-1]
        return FakeResp({"id": vid, "aliases": ["CVE-1"], "database_specific": {"severity": "high"}})


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(osv, "CACHE_DIR", tmp_path / "cache")


def pkg(name, version="1.0.0"):
    return Package(name=name, version=version, ecosystem="pypi")


def test_network_failure_is_error_not_clean():
    res = osv.query_osv_batch([pkg("a")], session=FakeSession(fail=True))
    s = osv.summarize_vulns(res["pypi:a@1.0.0"])
    assert s["status"] == "error"
    assert s["count"] is None


def test_clean_and_vulnerable_in_one_batch():
    session = FakeSession({"bad": ["GHSA-1", "PYSEC-2"]})
    res = osv.query_osv_batch([pkg("good"), pkg("bad")], session=session)
    assert session.posts == 1
    good = osv.summarize_vulns(res["pypi:good@1.0.0"])
    bad = osv.summarize_vulns(res["pypi:bad@1.0.0"])
    assert good == {"status": "ok", "count": 0, "ids": [], "aliases": [], "severities": []}
    assert bad["count"] == 2 and bad["ids"] == ["GHSA-1", "PYSEC-2"]
    assert bad["severities"][0]["label"] == "HIGH"


def test_unpinned_versions_are_skipped_not_queried():
    session = FakeSession()
    res = osv.query_osv_batch([pkg("r", ">=2.0"), pkg("n", "*")], session=session)
    assert session.posts == 0
    assert all(r["status"] == "skipped" for r in res.values())


def test_cache_hit_avoids_network_and_errors_are_not_cached():
    osv.query_osv_batch([pkg("x")], session=FakeSession(fail=True))
    s2 = FakeSession()
    osv.query_osv_batch([pkg("x")], session=s2)
    assert s2.posts == 1  # the failure was not cached
    s3 = FakeSession(fail=True)
    res = osv.query_osv_batch([pkg("x")], session=s3)
    assert s3.posts == 0 and res["pypi:x@1.0.0"]["status"] == "ok"


def test_pagination_is_followed():
    class Paged(FakeSession):
        def post(self, url, json, timeout):
            self.posts += 1
            q = json["queries"][0]
            if "page_token" not in q:
                return FakeResp({"results": [{"vulns": [{"id": "A"}], "next_page_token": "t"}]})
            return FakeResp({"results": [{"vulns": [{"id": "B"}]}]})

    res = osv.query_osv_batch([pkg("p")], session=Paged())
    assert osv.summarize_vulns(res["pypi:p@1.0.0"])["ids"] == ["A", "B"]


def test_summarize_none_is_not_queried():
    assert osv.summarize_vulns(None)["status"] == "not_queried"
