"""Regressions for the fourteenth review round."""
from __future__ import annotations

import json
import os
from pathlib import Path

from conftest import PASSWORD, confirmed
from hermes_warden import broker as broker_mod

GH = "11111111-1111-1111-1111-111111111111"


def unlock(b):
    assert b.call("unlock", password=PASSWORD)["ok"]


def _set_uris(uris):
    state_path = Path(os.environ["FAKE_BW_STATE"])
    state = json.loads(state_path.read_text())
    for i in state["items"]:
        if i["id"] == GH:
            i["login"]["uris"] = uris
    state_path.write_text(json.dumps(state))


def test_uri_limit_does_not_depend_on_current_urls(broker):
    unlock(broker)
    _set_uris([{"uri": "https://hooks.example.com/services/T0SECRET123", "match": None}])
    fill = [{"uri": f"https://f{i}.example/"} for i in range(30)]
    for guess in ("https://hooks.example.com/services/WRONG", "https://hooks.example.com/services/T0SECRET123"):
        res, prompt = confirmed(broker, broker.call, "edit", object="item", id=GH, patch={},
                                append_uris=fill + [{"uri": guess}], accept=False)
        assert res["code"] == "not_confirmed", res
    assert broker.call("edit", object="item", id=GH, patch={},
                       append_uris=[{"uri": f"https://f{i}.example/"} for i in range(51)])["code"] == "invalid"


def test_only_vault_details_are_cut(broker):
    unlock(broker)
    _set_uris([{"uri": "https://x.example/" + "a" * 150, "match": None}] * 5)
    fill = [{"uri": f"https://{'b' * 60}{i}.example/"} for i in range(20)]
    res, prompt = confirmed(broker, broker.call, "edit", object="item", id=GH, patch={}, append_uris=fill, accept=False)
    msg = prompt["message"]
    assert res["code"] == "not_confirmed" and "cut here" in msg and len(msg) <= broker_mod.MAX_CONFIRM
    assert all(f"{'b' * 60}{i}.example" in msg for i in range(20))  # what the agent sends is never cut
    big = [{"uri": f"https://{'b' * 60}{i}.example/"} for i in range(40)]
    res = broker.call("edit", object="item", id=GH, patch={}, append_uris=big)
    assert res["code"] == "invalid"  # too long to show whole: refused, by what the agent sent alone


def test_dates_checked_on_the_calendar():
    assert not broker_mod._valid_date("2026-13-45")
    assert not broker_mod._valid_date("2026-12-31T25:00")
    assert broker_mod._valid_date("2026-12-31T23:59:59Z") and broker_mod._valid_date("2026-12-31 23:59")


def test_bad_match_is_a_clear_error(broker):
    unlock(broker)
    res = broker.call("edit", object="item", id=GH, patch={"login": {"uris": [{"uri": "https://a.example", "match": [1]}]}})
    assert res["code"] == "invalid" and "match is one of" in res["error"]
