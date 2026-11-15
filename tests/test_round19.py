"""Regressions for the nineteenth review round."""
from __future__ import annotations

from conftest import PASSWORD, confirmed

GH = "11111111-1111-1111-1111-111111111111"
O, CA, CB = "aaaaaaaa-0000-0000-0000-000000000001", "cccccccc-0000-0000-0000-00000000000a", "cccccccc-0000-0000-0000-00000000000b"


def unlock(b):
    assert b.call("unlock", password=PASSWORD)["ok"]


def test_section_replaced_by_scalar_refused(broker):
    unlock(broker)
    for bad in ("", [], 0, False, None):
        res = broker.call("exec", args=["edit", "item", GH], json={"login": bad})
        assert res["code"] == "invalid", (bad, res)


def test_org_and_collections_shown(broker):
    unlock(broker)
    res, prompt = confirmed(broker, broker.call, "edit", object="item", id=GH, accept=False,
                            patch={"organizationId": O, "collectionIds": [CA, CB]})
    assert f"Organization: {O}; collections: {CA}, {CB}" in prompt["message"]


def test_type_name_and_reprompt_flag_normalised(broker):
    unlock(broker)
    res = broker.call("edit", object="item", id=GH, patch={"type": "login"})
    assert res["ok"], res
    assert broker.call("edit", object="item", id=GH, patch={"type": "spaceship"})["code"] == "invalid"


def test_edit_without_id_is_clear(broker):
    unlock(broker)
    for obj in ("item", "folder"):
        res = broker.call("exec", args=["edit", obj], json={"name": "x"})
        assert res["code"] == "invalid" and "needs an id" in res["error"]


def test_marker_error_names_paths(broker):
    unlock(broker)
    res = broker.call("edit", object="item", id=GH, patch={"login": {"password": "<hidden>"}})
    assert res["code"] == "invalid" and "login.password" in res["error"]


def test_round20_values_checked(broker):
    unlock(broker)
    for patch in ({"favorite": "false"}, {"reprompt": "true"}, {"organizationId": "x" * 58}, {"collectionIds": "c"},
                  {"login": {"password": ["guess"]}}, {"passwordHistory": "x"}):
        assert broker.call("edit", object="item", id=GH, patch=patch)["code"] == "invalid", patch
    # bw's template shape: null sections of other types, null collections and empty lists are no-ops
    res = broker.call("edit", object="item", id=GH, patch={"name": "GitHub", "card": None, "collectionIds": None})
    assert res["ok"], res


def test_exposed_non_login_says_so(broker):
    unlock(broker)
    items = broker.call("exec", args=["list", "items"])["data"]
    note = next(i for i in items if i["type"] != "login")
    res = broker.call("exec", args=["get", "exposed", note["id"]])
    assert res["code"] == "invalid" and res["error"] == "Not a login."


def test_round21_hardening(broker):
    unlock(broker)
    for patch in ({"key": "a" * 88}, {"login": {"fields": [1]}}, {"fields": [{"name": "plan", "value": {"a": "x"}}]}):
        assert broker.call("edit", object="item", id=GH, patch=patch)["code"] == "invalid", patch
    item = broker.call("exec", args=["get", "item", GH])["data"]
    body = {k: v for k, v in item.items() if k not in ("login", "notes", "fields")}
    body.update(name="GitHub", attachments=[{"id": "a", "fileName": "f"}], passwordHistory=None)
    res = broker.call("exec", args=["edit", "item", GH], json=body)
    assert res["ok"], res  # a read object without secrets round-trips: server keys dropped
