"""Responses created by the TypeScript keymaster, verified by the Python one.

The documents are those a real Gatekeeper resolved for the responses, and the
TypeScript suite verifies the opposite direction from the same fixture, which
tests/keymaster/generate-response-interop-vectors.mjs produces (#1300).
"""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any

import pytest

from keymaster import Keymaster

from .helpers import FakeWalletStore, run

FIXTURE = json.loads(
    (Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "response-interop.json").read_text()
)
DIRECTION = FIXTURE["typescriptToPython"]


class FixtureGatekeeper:
    def __init__(self, documents: dict[str, Any]) -> None:
        self.documents = documents

    async def list_registries(self) -> list[str]:
        return ["local", "hyperswarm"]

    async def resolve_did(self, did: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
        if did not in self.documents:
            return {"didResolutionMetadata": {"error": "notFound"}, "didDocumentMetadata": {}}
        return deepcopy(self.documents[did])

    # Verification only reads; a write here would be a defect.
    async def create_did(self, operation: dict[str, Any]) -> str:
        raise AssertionError("fixture Gatekeeper is read-only")


@pytest.fixture
def verifier(monkeypatch) -> Keymaster:
    # The generator encrypts fixture wallets with the suites' one iteration.
    monkeypatch.setenv("PBKDF2_ITERATIONS", "1")
    store = FakeWalletStore()
    store.save_wallet(DIRECTION["verifier"]["wallet"])
    keymaster = Keymaster(
        gatekeeper=FixtureGatekeeper(DIRECTION["documents"]),
        wallet_store=store,
        passphrase=FIXTURE["passphrase"],
    )
    run(keymaster.set_current_id(DIRECTION["verifier"]["name"]))
    return keymaster


def test_typescript_responses_use_presentation_dids(verifier):
    for response_did in DIRECTION["responses"].values():
        [entry] = run(verifier.decrypt_json(response_did))["response"]["credentials"]
        assert entry["vc"].startswith("did:cid:")
        assert entry["vp"].startswith("did:cid:")


@pytest.mark.parametrize("label", ["valid", "revoked"])
def test_typescript_responses_verify_as_the_typescript_verifier_did(verifier, label):
    verified = run(verifier.verify_response(DIRECTION["responses"][label]))
    vps = verified.get("vps") or []

    assert {
        "match": verified["match"],
        "issuers": [vp.get("issuer") for vp in vps],
        "subjects": [(vp.get("credentialSubject") or {}).get("id") for vp in vps],
    } == DIRECTION["expected"][label]
