import httpx
import pytest

from ir_sentinel.intel import association, configured_key, enrich, lookup
from ir_sentinel.investigation import investigate
from ir_sentinel.models import Indicator
from ir_sentinel.storage import private_dir, user_path, write_json


def indicator(value="8.8.8.8", kind="ipv4"):
    return Indicator(
        kind=kind, value=value, refs=["packet:1"], first_seen=1700000000, last_seen=1700000010
    )


def test_private_indicator_never_requests_network():
    def forbidden(request):
        pytest.fail("Private indicator was disclosed")

    with httpx.Client(transport=httpx.MockTransport(forbidden)) as client:
        assert lookup(client, indicator("10.0.0.1"))["status"] == "skipped"


def test_provider_provenance_and_timing():
    def handler(request):
        assert (
            str(request.url)
            == "https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general"
        )
        return httpx.Response(
            200,
            json={
                "pulse_info": {
                    "count": 1,
                    "pulses": [
                        {
                            "id": "reported-id",
                            "name": "Provider claim",
                            "adversary": "Reported actor",
                            "created": "2025-01-01T00:00:00Z",
                        }
                    ],
                }
            },
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = lookup(client, indicator())
    assert result["actor_attribution"] == "unknown"
    assert result["associations"][0]["publication_timing"] == "published_after_observation"
    assert result["associations"][0]["confidence"] == "low"
    assert result["evidence_refs"] == ["packet:1"] and result["retrieved_at"]


@pytest.mark.parametrize("code", [401, 403, 404, 429, 500])
def test_provider_failures_are_inconclusive(code):
    with httpx.Client(
        transport=httpx.MockTransport(lambda req: httpx.Response(code))
    ) as client:
        result = lookup(client, indicator())
    assert result["status"] == "error" and result["actor_attribution"] == "unknown"


@pytest.mark.parametrize("payload", [{}, [], {"pulse_info": {"pulses": ["bad"]}}])
def test_malformed_provider_data(payload):
    with httpx.Client(
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json=payload))
    ) as client:
        assert lookup(client, indicator())["status"] == "error"


def test_redirect_not_followed():
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda req: httpx.Response(
                302, headers={"location": "https://untrusted.invalid/key"}
            )
        ),
        follow_redirects=False,
    ) as client:
        assert lookup(client, indicator())["status"] == "error"


def test_hash_has_no_invented_observation_time():
    item = Indicator(kind="sha256", value="a" * 64, refs=["hash:input"])
    assert association({"created": "2020-01-01"}, item)["publication_timing"] == "unknown"


def test_key_permissions_and_enrichment_scope(store):
    case = investigate(store, hash_value="a" * 64)
    assert enrich(store, case.case_id)["status"] == "unconfigured"
    path = private_dir(user_path("config")) / "otx.json"
    write_json(path, {"key": "test-key"})
    assert configured_key() == "test-key"
    with pytest.raises(ValueError, match="observed"):
        enrich(store, case.case_id, ["8.8.8.8"])
    path.chmod(0o644)
    with pytest.raises(PermissionError):
        configured_key()
