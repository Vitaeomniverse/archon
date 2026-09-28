// Cross-port challenge-response fixtures (#1300).
//
// Runs the TypeScript Keymaster (in process) and the Python Keymaster (its
// CLI, over HTTP) against one in-memory Gatekeeper. Each direction has the
// issuer and holder in one port and the verifier in the other, so every
// response is created by one port and verified live by the other before the
// fixture is written. A fixture carries the Gatekeeper's resolved documents,
// the verifier's wallet and the expected results, so each port's unit suite
// can re-verify the other port's responses without the other runtime.
//
// Run from the repo root after `npm run build` and
// `npm run build --prefix services/gatekeeper/server`, with the repo .venv
// holding the Python keymaster:
//   node tests/keymaster/generate-response-interop-vectors.mjs
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Gatekeeper from '../../packages/gatekeeper/dist/esm/gatekeeper.js';
import DbJsonMemory from '../../packages/gatekeeper/dist/esm/db/json-memory.js';
import MemoryClient from '../../packages/ipfs/dist/esm/memory-client.js';
import Keymaster from '../../packages/keymaster/dist/esm/keymaster.js';
import WalletJsonMemory from '../../packages/keymaster/dist/esm/db/json-memory.js';
import CipherNode from '../../packages/cipher/dist/esm/cipher-node.js';
import { createGatekeeperApp } from '../../services/gatekeeper/server/dist/gatekeeper-api.js';
import gatekeeperConfig from '../../services/gatekeeper/server/dist/config.js';

const PASSPHRASE = 'passphrase';
// Both unit suites derive wallet keys with one PBKDF2 iteration, so the
// fixture wallets must be encrypted the same way. The Python CLI inherits it.
process.env.PBKDF2_ITERATIONS = '1';
const SCHEMA = {
    $schema: 'http://json-schema.org/draft-07/schema#',
    type: 'object',
    properties: { email: { type: 'string', format: 'email' } },
    required: ['email'],
};
const OUTPUT = 'tests/fixtures/response-interop.json';

const ipfs = new MemoryClient();
await ipfs.start();
const gatekeeper = new Gatekeeper({ db: new DbJsonMemory('response-interop'), ipfs, registries: ['local', 'hyperswarm'] });
const { app } = createGatekeeperApp({
    gatekeeper, ready: true, httpLogging: false,
    config: { ...gatekeeperConfig, adminApiKey: '', fallbackURL: '', confirmFallbackURL: '' },
});
const server = await new Promise(resolve => {
    const listening = app.listen(0, '127.0.0.1', () => resolve(listening));
});
const gatekeeperUrl = `http://127.0.0.1:${server.address().port}`;
const tempDir = mkdtempSync(join(tmpdir(), 'response-interop-'));

async function typescriptKeymaster() {
    const wallet = new WalletJsonMemory();
    const keymaster = new Keymaster({ gatekeeper, wallet, cipher: new CipherNode(), passphrase: PASSPHRASE });
    await keymaster.loadOrCreateWallet();
    return { wallet, keymaster };
}

// One Python CLI invocation against the shared Gatekeeper and a wallet file.
function pythonKeymaster(name) {
    const walletPath = join(tempDir, `${name}.json`);
    // Asynchronous: the Gatekeeper serving these calls runs on this event loop.
    const run = async (...args) => (await promisify(execFile)('.venv/bin/python', ['-m', 'keymaster.cli', ...args], {
        env: { ...process.env, ARCHON_GATEKEEPER_URL: gatekeeperUrl, ARCHON_WALLET_PATH: walletPath, ARCHON_PASSPHRASE: PASSPHRASE },
    })).stdout.trim();
    const file = (label, content) => {
        const path = join(tempDir, `${name}-${label}.json`);
        writeFileSync(path, JSON.stringify(content));
        return path;
    };
    return { run, file, wallet: () => JSON.parse(readFileSync(walletPath, 'utf8')) };
}

const did = output => output.match(/did:cid:[a-zA-Z0-9]+/)[0];

// The documents a verifier reads: the response, its challenge, each
// credential and presentation, and the agents whose keys verify them.
async function documentsFor(dids) {
    const documents = {};
    for (const id of dids) {
        documents[id] = await gatekeeper.resolveDID(id);
        delete documents[id].didResolutionMetadata;
    }
    return documents;
}

function expectResult(label, actual, expected) {
    const summary = { match: actual.match, issuers: (actual.vps ?? []).map(vp => vp.issuer), subjects: (actual.vps ?? []).map(vp => vp.credentialSubject?.id) };
    if (JSON.stringify(summary) !== JSON.stringify(expected)) {
        throw new Error(`${label}: live verification ${JSON.stringify(summary)} != expected ${JSON.stringify(expected)}`);
    }
}

// Issuer and holder in TypeScript, verifier in Python.
async function typescriptToPython() {
    const { keymaster: ts } = await typescriptKeymaster();
    const py = pythonKeymaster('ts-to-python-verifier');

    const alice = await ts.createId('Alice');
    const carol = await ts.createId('Carol');
    await py.run('new-wallet');
    const victor = did(await py.run('create-id', 'Victor'));

    // One credential stays valid; the other is revoked after the response
    // presenting it. Separate schemas keep each response to one credential.
    await ts.setCurrentId('Alice');
    const keptSchema = await ts.createSchema(SCHEMA);
    const revokedSchema = await ts.createSchema(SCHEMA);
    const kept = await ts.issueCredential(await ts.bindCredential(carol, { schema: keptSchema, claims: { email: 'kept@example.com' } }));
    const revoked = await ts.issueCredential(await ts.bindCredential(carol, { schema: revokedSchema, claims: { email: 'revoked@example.com' } }));

    await ts.setCurrentId('Carol');
    await ts.acceptCredential(kept);
    await ts.acceptCredential(revoked);
    const keptChallenge = did(await py.run('create-challenge', py.file('kept', { credentials: [{ schema: keptSchema, issuers: [alice] }] })));
    const revokedChallenge = did(await py.run('create-challenge', py.file('revoked', { credentials: [{ schema: revokedSchema, issuers: [alice] }] })));
    const valid = await ts.createResponse(keptChallenge);
    const afterRevocation = await ts.createResponse(revokedChallenge);

    await ts.setCurrentId('Alice');
    await ts.revokeCredential(revoked);

    const expected = {
        valid: { match: true, issuers: [alice], subjects: [carol] },
        revoked: { match: false, issuers: [], subjects: [] },
    };
    const responses = { valid, revoked: afterRevocation };
    for (const [label, response] of Object.entries(responses)) {
        expectResult(`ts-to-python ${label}`, JSON.parse(await py.run('verify-response', response)), expected[label]);
    }

    await ts.setCurrentId('Carol');
    const presentations = [];
    for (const response of Object.values(responses)) {
        const { response: { credentials } } = await ts.decryptJSON(response);
        presentations.push(...credentials.flatMap(pair => [pair.vc, pair.vp]));
    }

    return {
        verifier: { name: 'Victor', did: victor, wallet: py.wallet() },
        responses,
        expected,
        documents: await documentsFor([alice, carol, victor, keptSchema, revokedSchema, keptChallenge, revokedChallenge,
            ...Object.values(responses), ...presentations]),
    };
}

// Issuer and holder in Python, verifier in TypeScript.
async function pythonToTypescript() {
    const py = pythonKeymaster('python-to-ts-holder');
    const { keymaster: ts, wallet } = await typescriptKeymaster();

    await py.run('new-wallet');
    const alice = did(await py.run('create-id', 'Alice'));
    const carol = did(await py.run('create-id', 'Carol'));
    const victor = await ts.createId('Victor');

    await py.run('use-id', 'Alice');
    const keptSchema = did(await py.run('create-schema', py.file('kept-schema', SCHEMA)));
    const revokedSchema = did(await py.run('create-schema', py.file('revoked-schema', SCHEMA)));
    const issue = async (schema, email) => {
        const bound = JSON.parse(await py.run('bind-credential', schema, carol));
        bound.credentialSubject.email = email;
        return did(await py.run('issue-credential', py.file(`credential-${email}`, bound)));
    };
    const kept = await issue(keptSchema, 'kept@example.com');
    const revoked = await issue(revokedSchema, 'revoked@example.com');

    await py.run('use-id', 'Carol');
    await py.run('accept-credential', kept);
    await py.run('accept-credential', revoked);
    const keptChallenge = await ts.createChallenge({ credentials: [{ schema: keptSchema, issuers: [alice] }] });
    const revokedChallenge = await ts.createChallenge({ credentials: [{ schema: revokedSchema, issuers: [alice] }] });
    const valid = did(await py.run('create-response', keptChallenge));
    const afterRevocation = did(await py.run('create-response', revokedChallenge));

    await py.run('use-id', 'Alice');
    await py.run('revoke-credential', revoked);

    const expected = {
        valid: { match: true, issuers: [alice], subjects: [carol] },
        revoked: { match: false, issuers: [], subjects: [] },
    };
    const responses = { valid, revoked: afterRevocation };
    for (const [label, response] of Object.entries(responses)) {
        expectResult(`python-to-ts ${label}`, await ts.verifyResponse(response), expected[label]);
    }

    const presentations = [];
    for (const response of Object.values(responses)) {
        const { response: { credentials } } = await ts.decryptJSON(response);
        presentations.push(...credentials.flatMap(pair => [pair.vc, pair.vp]));
    }

    return {
        verifier: { name: 'Victor', did: victor, wallet: await wallet.loadWallet() },
        responses,
        expected,
        documents: await documentsFor([alice, carol, victor, keptSchema, revokedSchema, keptChallenge, revokedChallenge,
            ...Object.values(responses), ...presentations]),
    };
}

try {
    const fixture = {
        passphrase: PASSPHRASE,
        typescriptToPython: await typescriptToPython(),
        pythonToTypescript: await pythonToTypescript(),
    };
    writeFileSync(OUTPUT, JSON.stringify(fixture, null, 2) + '\n');
    console.log(`wrote ${OUTPUT}`);
}
finally {
    server.close();
    await ipfs.stop();
    rmSync(tempDir, { recursive: true, force: true });
}
