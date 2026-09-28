import { writeFileSync, rmSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { archon, archonFails, resetAll, parseDid, dockerExec } from './helpers.ts';

const exec = promisify(execFile);
const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

// Historical response verification against the Keymaster service and a real
// Gatekeeper, so each keymaster/gatekeeper pairing in the CI matrix exercises
// the version selectors end to end. Gatekeeper reports times to the second,
// so each captured cutoff is separated from the events around it by more
// than a second.

let tempDir: string;
let responseDid: string;
let beforeResponse: string;
let beforeRevocation: string;
let afterRevocation: string;

async function copyToContainer(name: string, content: unknown): Promise<string> {
    const file = join(tempDir, name);
    writeFileSync(file, JSON.stringify(content));
    await exec('docker', ['compose', 'cp', file, `cli:/app/share/${name}`]);
    return `share/${name}`;
}

async function verify(...args: string[]): Promise<{ match: boolean }> {
    return JSON.parse(await archon('verify-response', responseDid, ...args));
}

beforeAll(async () => {
    tempDir = mkdtempSync(join(tmpdir(), 'archon-cli-response-'));

    await archon('new-wallet');
    const verifier = parseDid(await archon('create-id', '-r', 'local', 'qa-verifier'));
    const holder = parseDid(await archon('create-id', '-r', 'local', 'qa-holder'));

    await archon('use-id', 'qa-verifier');
    const schema = parseDid(await archon('create-schema', 'share/schema/social-media.json'));
    const bound = JSON.parse(await archon('bind-credential', schema, holder));
    const credential = parseDid(await archon('issue-credential', await copyToContainer('qa-response-vc.json', bound)));

    await archon('use-id', 'qa-holder');
    expect(await archon('accept-credential', credential)).toContain('OK');

    await archon('use-id', 'qa-verifier');
    const challengeFile = await copyToContainer('qa-response-challenge.json', {
        credentials: [{ schema, issuers: [verifier] }],
    });
    const challenge = parseDid(await archon('create-challenge', challengeFile));

    beforeResponse = new Date().toISOString();
    await sleep(1500);

    await archon('use-id', 'qa-holder');
    responseDid = parseDid(await archon('create-response', challenge));

    await sleep(1500);
    beforeRevocation = new Date().toISOString();
    await sleep(1500);

    await archon('use-id', 'qa-verifier');
    expect(await archon('revoke-credential', credential)).toContain('OK');

    await sleep(1500);
    afterRevocation = new Date().toISOString();
}, 90000);

afterAll(async () => {
    try {
        rmSync(tempDir, { recursive: true, force: true });
    } catch { /* ignore */ }

    try {
        await dockerExec('cli', 'rm', '-f', '/app/share/qa-response-vc.json', '/app/share/qa-response-challenge.json');
    } catch { /* ignore */ }

    await resetAll();
});

describe('verify-response historical selectors', () => {
    test('reflects the revocation by default', async () => {
        expect((await verify()).match).toBe(false);
    });

    test('verifies as of a time before the revocation', async () => {
        expect((await verify('--version-time', beforeRevocation)).match).toBe(true);
    });

    test('reflects the revocation as of a time after it', async () => {
        expect((await verify('--version-time', afterRevocation)).match).toBe(false);
    });

    test('selects a response version within the versionTime context', async () => {
        expect((await verify('-t', beforeRevocation, '-s', '1')).match).toBe(true);
        expect((await verify('-t', afterRevocation, '-s', '1')).match).toBe(false);

        const { status, stderr } = await archonFails('verify-response', responseDid, '-t', afterRevocation, '-s', '2');
        expect(status).toBe(1);
        expect(stderr).toContain('responseDID version 2 not found');
    });

    test('refuses a time before the response existed', async () => {
        const { status, stderr } = await archonFails('verify-response', responseDid, '-t', beforeResponse);
        expect(status).toBe(1);
        expect(stderr).toContain('responseDID did not exist at versionTime');
    });

    test('rejects malformed selectors', async () => {
        const offsetless = await archonFails('verify-response', responseDid, '-t', beforeRevocation.replace('Z', ''));
        expect(offsetless.stderr).toContain('versionTime');

        const sequenceOnly = await archonFails('verify-response', responseDid, '-s', '1');
        expect(sequenceOnly.stderr).toContain('versionSequence requires versionTime');
    });
});
