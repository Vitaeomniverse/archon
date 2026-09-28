from __future__ import annotations

from copy import deepcopy
import json

import pytest

from keymaster import KeymasterError, UnknownIDError

from .helpers import MOCK_SCHEMA, run


def test_create_response_selects_matching_held_credentials(testbed):
    alice = run(testbed.keymaster.create_id("Alice"))
    bob = run(testbed.keymaster.create_id("Bob"))
    run(testbed.keymaster.create_id("Victor"))

    run(testbed.keymaster.set_current_id("Alice"))
    schema_did = run(testbed.keymaster.create_schema(MOCK_SCHEMA))
    bound = run(testbed.keymaster.bind_credential(bob, {"schema": schema_did}))
    vc_did = run(testbed.keymaster.issue_credential(bound))

    run(testbed.keymaster.set_current_id("Bob"))
    assert run(testbed.keymaster.accept_credential(vc_did)) is True

    run(testbed.keymaster.set_current_id("Victor"))
    challenge_did = run(testbed.keymaster.create_challenge({"credentials": [{"schema": schema_did, "issuers": [alice]}]}))

    run(testbed.keymaster.set_current_id("Bob"))
    response_did = run(testbed.keymaster.create_response(challenge_did))
    response = run(testbed.keymaster.decrypt_json(response_did))["response"]

    assert response["challenge"] == challenge_did
    assert len(response["credentials"]) == 1
    assert response["credentials"][0]["vc"] == vc_did
    assert response["fulfilled"] == 1
    assert response["match"] is True


def test_create_response_rejects_invalid_or_non_challenge_dids(testbed):
    alice = run(testbed.keymaster.create_id("Alice"))

    with pytest.raises(UnknownIDError, match="Unknown ID"):
        run(testbed.keymaster.create_response("missing"))

    with pytest.raises(KeymasterError, match="Invalid parameter: challengeDID"):
        run(testbed.keymaster.create_response(alice))


def test_verify_response_handles_empty_and_unmatched_challenges(testbed):
    run(testbed.keymaster.create_id("Alice"))
    bob = run(testbed.keymaster.create_id("Bob"))

    run(testbed.keymaster.set_current_id("Alice"))
    empty_challenge = run(testbed.keymaster.create_challenge())

    run(testbed.keymaster.set_current_id("Bob"))
    response_did = run(testbed.keymaster.create_response(empty_challenge))

    run(testbed.keymaster.set_current_id("Alice"))
    verified = run(testbed.keymaster.verify_response(response_did))
    assert verified == {
        "challenge": empty_challenge,
        "credentials": [],
        "requested": 0,
        "fulfilled": 0,
        "match": True,
        "vps": [],
        "responder": bob,
    }

    run(testbed.keymaster.set_current_id("Bob"))
    unmatched_schema = run(testbed.keymaster.create_schema(MOCK_SCHEMA))
    run(testbed.keymaster.set_current_id("Alice"))
    challenge = run(testbed.keymaster.create_challenge({"credentials": [{"schema": unmatched_schema}]}))
    run(testbed.keymaster.set_current_id("Bob"))
    unmatched_response = run(testbed.keymaster.create_response(challenge))
    run(testbed.keymaster.set_current_id("Alice"))
    unmatched = run(testbed.keymaster.verify_response(unmatched_response))
    assert unmatched["match"] is False
    assert unmatched["requested"] == 1
    assert unmatched["fulfilled"] == 0
    assert unmatched["vps"] == []


def test_verify_response_accepts_updated_credentials_and_detects_revocation(testbed):
    run(testbed.keymaster.create_id("Alice"))
    carol = run(testbed.keymaster.create_id("Carol"))
    run(testbed.keymaster.create_id("Victor"))

    run(testbed.keymaster.set_current_id("Alice"))
    schema_did = run(testbed.keymaster.create_schema(MOCK_SCHEMA, {"registry": "local"}))
    bound = run(testbed.keymaster.bind_credential(carol, {"schema": schema_did}))
    vc_did = run(testbed.keymaster.issue_credential(bound, {"registry": "local"}))

    run(testbed.keymaster.set_current_id("Carol"))
    assert run(testbed.keymaster.accept_credential(vc_did)) is True

    run(testbed.keymaster.set_current_id("Alice"))
    updated = run(testbed.keymaster.get_credential(vc_did))
    updated["credentialSubject"]["email"] = "updated@email.com"
    assert run(testbed.keymaster.update_credential(vc_did, updated)) is True

    run(testbed.keymaster.set_current_id("Victor"))
    challenge_did = run(testbed.keymaster.create_challenge({"credentials": [{"schema": schema_did}]}))

    run(testbed.keymaster.set_current_id("Carol"))
    response_did = run(testbed.keymaster.create_response(challenge_did))

    run(testbed.keymaster.set_current_id("Victor"))
    verified = run(testbed.keymaster.verify_response(response_did))
    assert verified["match"] is True
    assert verified["fulfilled"] == 1
    assert len(verified["vps"]) == 1

    run(testbed.keymaster.set_current_id("Alice"))
    assert run(testbed.keymaster.revoke_credential(vc_did)) is True

    run(testbed.keymaster.set_current_id("Victor"))
    revoked = run(testbed.keymaster.verify_response(response_did))
    assert revoked["match"] is False
    assert revoked["vps"] == []


def test_verify_response_rejects_non_response_asset(testbed):
    alice = run(testbed.keymaster.create_id("Alice"))
    did = run(testbed.keymaster.encrypt_json({"plain": True}, alice, {"registry": "local"}))

    with pytest.raises(KeymasterError, match="responseDID not a valid challenge response"):
        run(testbed.keymaster.verify_response(did))


T0 = "2026-09-01T00:"


def _at(minute: int) -> str:
    return f"{T0}{minute:02d}:00.000Z"


def _historical_response(testbed):
    # Minute 0: Alice issues a credential to Carol. Minute 10: Victor
    # challenges and Carol responds.
    km = testbed.keymaster
    testbed.gatekeeper.historical = True
    testbed.gatekeeper.now = _at(0)
    alice = run(km.create_id("Alice"))
    carol = run(km.create_id("Carol"))
    run(km.create_id("Victor"))

    run(km.set_current_id("Alice"))
    schema_did = run(km.create_schema(MOCK_SCHEMA))
    bound = run(km.bind_credential(carol, {"schema": schema_did}))
    vc_did = run(km.issue_credential(bound))
    run(km.set_current_id("Carol"))
    assert run(km.accept_credential(vc_did)) is True

    testbed.gatekeeper.now = _at(10)
    run(km.set_current_id("Victor"))
    challenge_did = run(km.create_challenge({"credentials": [{"schema": schema_did, "issuers": [alice]}]}))
    run(km.set_current_id("Carol"))
    response_did = run(km.create_response(challenge_did))
    return {"alice": alice, "carol": carol, "vc": vc_did, "challenge": challenge_did, "response": response_did}


def _verify_at(testbed, response_did, minute=None, version_sequence=None):
    run(testbed.keymaster.set_current_id("Victor"))
    options = {} if minute is None else {"versionTime": _at(minute)}
    if version_sequence is not None:
        options["versionSequence"] = version_sequence
    return run(testbed.keymaster.verify_response(response_did, options))


def test_verify_response_historical_revocation(testbed):
    ctx = _historical_response(testbed)

    testbed.gatekeeper.now = _at(20)
    run(testbed.keymaster.set_current_id("Alice"))
    run(testbed.keymaster.revoke_credential(ctx["vc"]))

    assert _verify_at(testbed, ctx["response"])["match"] is False

    before = _verify_at(testbed, ctx["response"], 15)
    assert before["match"] is True
    assert [vp["credentialSubject"]["id"] for vp in before["vps"]] == [ctx["carol"]]
    assert before["responder"] == ctx["carol"]

    assert _verify_at(testbed, ctx["response"], 25)["match"] is False


def test_verify_response_historical_challenge(testbed):
    ctx = _historical_response(testbed)

    testbed.gatekeeper.now = _at(20)
    run(testbed.keymaster.set_current_id("Alice"))
    extra = run(testbed.keymaster.create_schema(MOCK_SCHEMA))
    run(testbed.keymaster.set_current_id("Victor"))
    original = run(testbed.keymaster.resolve_asset(ctx["challenge"]))["challenge"]
    run(testbed.keymaster.merge_data(ctx["challenge"], {
        "challenge": {"credentials": [*original["credentials"], {"schema": extra, "issuers": [ctx["alice"]]}]},
    }))

    assert _verify_at(testbed, ctx["response"])["match"] is False
    assert _verify_at(testbed, ctx["response"], 15)["match"] is True


def test_verify_response_rejects_a_challenge_revoked_by_the_cutoff(testbed):
    ctx = _historical_response(testbed)

    testbed.gatekeeper.now = _at(20)
    run(testbed.keymaster.set_current_id("Victor"))
    run(testbed.keymaster.revoke_did(ctx["challenge"]))

    with pytest.raises(KeymasterError, match="Invalid parameter: challengeDID"):
        _verify_at(testbed, ctx["response"])
    assert _verify_at(testbed, ctx["response"], 15)["match"] is True
    with pytest.raises(KeymasterError, match="Invalid parameter: challengeDID"):
        _verify_at(testbed, ctx["response"], 25)


def test_verify_response_historical_response_version(testbed):
    ctx = _historical_response(testbed)
    km = testbed.keymaster

    testbed.gatekeeper.now = _at(20)
    run(km.set_current_id("Victor"))
    empty = run(km.create_challenge({"credentials": []}))
    run(km.set_current_id("Carol"))
    other = run(km.create_response(empty))
    data = run(km.resolve_did(other))["didDocumentData"]
    run(km.update_did(ctx["response"], {"didDocumentData": data}))

    assert _verify_at(testbed, ctx["response"])["challenge"] == empty
    assert _verify_at(testbed, ctx["response"], 15)["challenge"] == ctx["challenge"]
    assert _verify_at(testbed, ctx["response"], 25)["challenge"] == empty

    first = _verify_at(testbed, ctx["response"], 30, 1)
    assert first["challenge"] == ctx["challenge"]
    assert first["match"] is True
    assert _verify_at(testbed, ctx["response"], 30, 2)["challenge"] == empty

    with pytest.raises(KeymasterError, match="Invalid parameter: responseDID version 2 is later than versionTime"):
        _verify_at(testbed, ctx["response"], 15, 2)
    with pytest.raises(KeymasterError, match="Invalid parameter: responseDID version 3 not found"):
        _verify_at(testbed, ctx["response"], 30, 3)


def test_verify_response_historical_refuses_cutoffs_before_creation(testbed):
    ctx = _historical_response(testbed)
    km = testbed.keymaster

    with pytest.raises(KeymasterError, match="Invalid parameter: responseDID did not exist at versionTime"):
        _verify_at(testbed, ctx["response"], 5)

    # A response whose challenge was created after the cutoff.
    testbed.gatekeeper.now = _at(20)
    run(km.set_current_id("Victor"))
    later = run(km.create_challenge())
    victor = run(km.fetch_id_info())["did"]
    testbed.gatekeeper.now = _at(10)
    run(km.set_current_id("Carol"))
    forged = run(km.encrypt_json({"response": {"challenge": later, "credentials": []}}, victor))

    with pytest.raises(KeymasterError, match="Invalid parameter: challenge did not exist at versionTime"):
        _verify_at(testbed, forged, 15)


def test_verify_response_rejects_malformed_selectors(testbed):
    ctx = _historical_response(testbed)
    km = testbed.keymaster
    run(km.set_current_id("Victor"))

    with pytest.raises(KeymasterError, match="Invalid parameter: versionSequence requires versionTime"):
        run(km.verify_response(ctx["response"], {"versionSequence": 1}))
    malformed = ["yesterday", "0", "01/01/2026", "2026/09/01", "2026-09-01", "2026-09-01T00:15:00",
                 "2026-02-29T00:00:00Z", "2026-04-31T00:00:00Z", "2026-09-01T24:00:00Z", "2026-09-01T00:00:60Z",
                 "2026-09-01T00:15:00+24:00", "0000-01-01T00:00:00Z"]
    for version_time in malformed:
        with pytest.raises(KeymasterError, match="Invalid parameter: versionTime"):
            run(km.verify_response(ctx["response"], {"versionTime": version_time}))
    for version_time in ["2026-09-01t00:15:00.123456789z", "2026-09-01T02:15:00+02:00"]:
        assert run(km.verify_response(ctx["response"], {"versionTime": version_time}))["match"] is True
    with pytest.raises(KeymasterError, match="Invalid parameter: versionSequence"):
        run(km.verify_response(ctx["response"], {"versionTime": _at(15), "versionSequence": 0}))


def test_create_response_binds_each_presentation_to_its_credential(testbed):
    ctx = _historical_response(testbed)
    km = testbed.keymaster

    run(km.set_current_id("Victor"))
    response = run(km.decrypt_json(ctx["response"]))["response"]
    [entry] = response["credentials"]
    assert entry["vc"] == ctx["vc"]
    assert isinstance(entry["vp"], str) and entry["vp"] != ctx["vc"]

    vc_hash = run(km.resolve_asset(entry["vc"]))["encrypted"]["cipher_hash"]
    vp_hash = run(km.resolve_asset(entry["vp"]))["encrypted"]["cipher_hash"]
    assert vc_hash and vc_hash == vp_hash
    assert run(km.decrypt_json(entry["vp"]))["credentialSubject"]["id"] == ctx["carol"]


def test_verify_response_historical_credential_update(testbed):
    ctx = _historical_response(testbed)
    km = testbed.keymaster

    testbed.gatekeeper.now = _at(20)
    run(km.set_current_id("Alice"))
    updated = run(km.get_credential(ctx["vc"]))
    updated["credentialSubject"]["email"] = "updated@email.com"
    assert run(km.update_credential(ctx["vc"], updated)) is True

    # The presentation no longer matches the updated credential.
    assert _verify_at(testbed, ctx["response"])["match"] is False
    assert _verify_at(testbed, ctx["response"], 15)["match"] is True
    assert _verify_at(testbed, ctx["response"], 25)["match"] is False


def test_verify_response_historical_presentation(testbed):
    ctx = _historical_response(testbed)
    km = testbed.keymaster

    run(km.set_current_id("Victor"))
    [entry] = run(km.decrypt_json(ctx["response"]))["response"]["credentials"]

    testbed.gatekeeper.now = _at(20)
    run(km.set_current_id("Carol"))
    assert run(km.revoke_did(entry["vp"])) is True

    assert _verify_at(testbed, ctx["response"])["match"] is False
    assert _verify_at(testbed, ctx["response"], 15)["match"] is True
    assert _verify_at(testbed, ctx["response"], 25)["match"] is False


def test_verify_response_rejects_a_credential_without_a_valid_issuer_proof(testbed):
    km = testbed.keymaster
    alice = run(km.create_id("Alice"))
    carol = run(km.create_id("Carol"))
    victor = run(km.create_id("Victor"))

    run(km.set_current_id("Alice"))
    schema_did = run(km.create_schema(MOCK_SCHEMA))
    bound = run(km.bind_credential(carol, {"schema": schema_did}))
    genuine = run(km.get_credential(run(km.issue_credential(bound))))

    # Carol claims Alice issued a credential Alice never signed. The
    # presentation's hash matches the credential DID, so only the proof check
    # can reject it.
    run(km.set_current_id("Carol"))
    forged = deepcopy(genuine)
    forged["credentialSubject"]["email"] = "forged@example.com"
    plaintext = json.dumps(forged, separators=(",", ":"))
    vc_did = run(km.encrypt_message(plaintext, carol, {"includeHash": True}))

    run(km.set_current_id("Victor"))
    challenge_did = run(km.create_challenge({"credentials": [{"schema": schema_did, "issuers": [alice]}]}))

    run(km.set_current_id("Carol"))
    vp_did = run(km.encrypt_message(plaintext, victor, {"includeHash": True}))
    response = {"challenge": challenge_did, "credentials": [{"vc": vc_did, "vp": vp_did}],
                "requested": 1, "fulfilled": 1, "match": True}
    response_did = run(km.encrypt_json({"response": response}, victor))

    run(km.set_current_id("Victor"))
    verified = run(km.verify_response(response_did))
    assert verified["match"] is False
    assert verified["vps"] == []


def test_verify_response_does_not_count_legacy_inline_credentials(testbed):
    # Before presentation DIDs, Python responses embedded the credential
    # itself. Nothing binds that copy to the credential DID, so it is not
    # counted; such responses are short-lived (validUntil defaults to an hour).
    ctx = _historical_response(testbed)
    km = testbed.keymaster

    run(km.set_current_id("Carol"))
    credential = run(km.get_credential(ctx["vc"]))
    victor = run(km.resolve_did("Victor"))["didDocument"]["id"]
    response = {"challenge": ctx["challenge"], "credentials": [{"vc": ctx["vc"], "vp": credential}],
                "requested": 1, "fulfilled": 1, "match": True}
    legacy = run(km.encrypt_json({"response": response}, victor))

    verified = _verify_at(testbed, legacy)
    assert verified["match"] is False
    assert verified["vps"] == []
