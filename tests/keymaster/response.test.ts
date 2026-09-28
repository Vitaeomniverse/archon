import { jest } from '@jest/globals';
import Gatekeeper from '@didcid/gatekeeper';
import Keymaster from '@didcid/keymaster';
import { ChallengeResponse } from '@didcid/keymaster/types';
import CipherNode from '@didcid/cipher/node';
import DbJsonMemory from '@didcid/gatekeeper/db/json-memory';
import WalletJsonMemory from '@didcid/keymaster/wallet/json-memory';
import { InvalidDIDError, ExpectedExceptionError, UnknownIDError } from '@didcid/common/errors';
import MemoryClient from '@didcid/ipfs/memory';
import { mockSchema } from './helper.ts';

let ipfs: MemoryClient;
let db: DbJsonMemory;
let gatekeeper: Gatekeeper;
let wallet: WalletJsonMemory;
let cipher: CipherNode;
let keymaster: Keymaster;

beforeAll(async () => {
    ipfs = new MemoryClient();
    await ipfs.start();
});

afterAll(async () => {
    if (ipfs) {
        await ipfs.stop();
    }
});

beforeEach(async () => {
    db = new DbJsonMemory('test');
    gatekeeper = new Gatekeeper({ db, ipfs, registries: ['local', 'hyperswarm', 'BTC:signet'] });
    wallet = new WalletJsonMemory();
    cipher = new CipherNode();
    keymaster = new Keymaster({ gatekeeper, wallet, cipher, passphrase: 'passphrase' });
    await keymaster.loadOrCreateWallet();
});

describe('createResponse', () => {
    it('should create a valid response to a simple challenge', async () => {
        const alice = await keymaster.createId('Alice');
        const bob = await keymaster.createId('Bob');
        await keymaster.createId('Victor');

        await keymaster.setCurrentId('Alice');

        const credentialDid = await keymaster.createSchema(mockSchema);
        const boundCredential = await keymaster.bindCredential(bob, { schema: credentialDid });
        const vcDid = await keymaster.issueCredential(boundCredential);

        await keymaster.setCurrentId('Bob');

        const ok = await keymaster.acceptCredential(vcDid);
        expect(ok).toBe(true);

        const wallet = await keymaster.loadWallet();
        expect(wallet.ids['Alice'].owned!.includes(vcDid));
        expect(wallet.ids['Bob'].held!.includes(vcDid));

        await keymaster.setCurrentId('Victor');

        const challenge = {
            credentials: [
                {
                    schema: credentialDid,
                    issuers: [alice]
                }
            ]
        };
        const challengeDID = await keymaster.createChallenge(challenge);

        await keymaster.setCurrentId('Bob');
        const responseDID = await keymaster.createResponse(challengeDID);
        const { response } = await keymaster.decryptJSON(responseDID) as { response: ChallengeResponse };

        expect(response.challenge).toBe(challengeDID);
        expect(response.credentials.length).toBe(1);
        expect(response.credentials[0].vc).toBe(vcDid);
    });

    it('should throw an exception on invalid challenge', async () => {
        const alice = await keymaster.createId('Alice');

        try {
            // @ts-expect-error Testing invalid usage, missing args
            await keymaster.createResponse();
            throw new ExpectedExceptionError();
        }
        catch (error: any) {
            expect(error.message).toBe(InvalidDIDError.type);
        }

        try {
            await keymaster.createResponse('mock');
            throw new ExpectedExceptionError();
        }
        catch (error: any) {
            expect(error.type).toBe(UnknownIDError.type);
        }

        try {
            await keymaster.createResponse('did:mock');
            throw new ExpectedExceptionError();
        }
        catch (error: any) {
            expect(error.type).toBe(InvalidDIDError.type);
        }

        try {
            await keymaster.createResponse('did:mock', { retries: 10, delay: 10 });
            throw new ExpectedExceptionError();
        }
        catch (error: any) {
            expect(error.type).toBe(InvalidDIDError.type);
        }

        try {
            await keymaster.createResponse(alice);
            throw new ExpectedExceptionError();
        }
        catch (error: any) {
            expect(error.message).toBe('Invalid parameter: challengeDID');
        }
    });
});

describe('verifyResponse', () => {
    it('should verify valid response to empty challenge', async () => {
        await keymaster.createId('Alice');
        const bob = await keymaster.createId('Bob');

        await keymaster.setCurrentId('Alice');
        const challengeDID = await keymaster.createChallenge();

        await keymaster.setCurrentId('Bob');
        const responseDID = await keymaster.createResponse(challengeDID);

        await keymaster.setCurrentId('Alice');
        const verify = await keymaster.verifyResponse(responseDID);

        const expected = {
            challenge: challengeDID,
            credentials: [],
            requested: 0,
            fulfilled: 0,
            match: true,
            vps: [],
            responder: bob,
        };

        expect(verify).toStrictEqual(expected);
    });

    it('should verify a valid response to a single credential challenge', async () => {
        await keymaster.createId('Alice');
        const carol = await keymaster.createId('Carol');
        await keymaster.createId('Victor');

        await keymaster.setCurrentId('Alice');

        const credential1 = await keymaster.createSchema(mockSchema);
        const bc1 = await keymaster.bindCredential(carol, { schema: credential1 });
        const vc1 = await keymaster.issueCredential(bc1);

        await keymaster.setCurrentId('Carol');

        await keymaster.acceptCredential(vc1);

        await keymaster.setCurrentId('Victor');

        const challenge = {
            credentials: [
                {
                    schema: credential1,
                },
            ]
        };
        const challengeDID = await keymaster.createChallenge(challenge);

        await keymaster.setCurrentId('Carol');
        const responseDID = await keymaster.createResponse(challengeDID);

        await keymaster.setCurrentId('Victor');

        const verify1 = await keymaster.verifyResponse(responseDID);

        expect(verify1.match).toBe(true);
        expect(verify1.challenge).toBe(challengeDID);
        expect(verify1.requested).toBe(1);
        expect(verify1.fulfilled).toBe(1);
        expect(verify1.vps!.length).toBe(1);
    });

    it('should not verify a invalid response to a single credential challenge', async () => {
        await keymaster.createId('Alice');
        await keymaster.createId('Carol');
        await keymaster.createId('Victor');

        await keymaster.setCurrentId('Alice');

        const credential1 = await keymaster.createSchema(mockSchema);

        await keymaster.setCurrentId('Victor');

        const challenge = {
            credentials: [
                {
                    schema: credential1,
                },
            ]
        };
        const challengeDID = await keymaster.createChallenge(challenge);

        await keymaster.setCurrentId('Carol');
        const responseDID = await keymaster.createResponse(challengeDID);

        await keymaster.setCurrentId('Victor');

        const verify1 = await keymaster.verifyResponse(responseDID);

        expect(verify1.match).toBe(false);
        expect(verify1.challenge).toBe(challengeDID);
        expect(verify1.requested).toBe(1);
        expect(verify1.fulfilled).toBe(0);
        expect(verify1.vps!.length).toBe(0);
    });

    it('should verify a response if credential is updated', async () => {
        await keymaster.createId('Alice');
        const carol = await keymaster.createId('Carol');
        await keymaster.createId('Victor');

        await keymaster.setCurrentId('Alice');

        const credential1 = await keymaster.createSchema(mockSchema);
        const bc1 = await keymaster.bindCredential(carol, { schema: credential1 });
        const vc1 = await keymaster.issueCredential(bc1);

        await keymaster.setCurrentId('Carol');
        await keymaster.acceptCredential(vc1);

        await keymaster.setCurrentId('Alice');
        const credential2 = (await keymaster.getCredential(vc1))!;
        // The claims live in credentialSubject; assigning a bare `credential`
        // field wrote somewhere the credential does not read, so the test named
        // "if credential is updated" was not updating one.
        credential2.credentialSubject!.email = 'updated@email.com';
        await keymaster.updateCredential(vc1, credential2);

        await keymaster.setCurrentId('Victor');

        const challenge = {
            credentials: [
                {
                    schema: credential1,
                },
            ]
        };

        const challengeDID = await keymaster.createChallenge(challenge);

        await keymaster.setCurrentId('Carol');
        const responseDID = await keymaster.createResponse(challengeDID);

        await keymaster.setCurrentId('Victor');

        const verify1 = await keymaster.verifyResponse(responseDID);

        expect(verify1.match).toBe(true);
        expect(verify1.challenge).toBe(challengeDID);
        expect(verify1.requested).toBe(1);
        expect(verify1.fulfilled).toBe(1);
        expect(verify1.vps!.length).toBe(1);
    });

    it('should demonstrate full workflow with credential revocations', async () => {
        const alice = await keymaster.createId('Alice', { registry: 'local' });
        const bob = await keymaster.createId('Bob', { registry: 'local' });
        const carol = await keymaster.createId('Carol', { registry: 'local' });
        await keymaster.createId('Victor', { registry: 'local' });

        await keymaster.setCurrentId('Alice');

        const schema1 = await keymaster.createSchema(mockSchema, { registry: 'local' });
        const schema2 = await keymaster.createSchema(mockSchema, { registry: 'local' });

        const bc1 = await keymaster.bindCredential(carol, { schema: schema1 });
        const bc2 = await keymaster.bindCredential(carol, { schema: schema2 });

        const vc1 = await keymaster.issueCredential(bc1, { registry: 'local' });
        const vc2 = await keymaster.issueCredential(bc2, { registry: 'local' });

        await keymaster.setCurrentId('Bob');

        const schema3 = await keymaster.createSchema(mockSchema, { registry: 'local' });
        const schema4 = await keymaster.createSchema(mockSchema, { registry: 'local' });

        const bc3 = await keymaster.bindCredential(carol, { schema: schema3 });
        const bc4 = await keymaster.bindCredential(carol, { schema: schema4 });

        const vc3 = await keymaster.issueCredential(bc3, { registry: 'local' });
        const vc4 = await keymaster.issueCredential(bc4, { registry: 'local' });

        await keymaster.setCurrentId('Carol');

        await keymaster.acceptCredential(vc1);
        await keymaster.acceptCredential(vc2);
        await keymaster.acceptCredential(vc3);
        await keymaster.acceptCredential(vc4);

        await keymaster.setCurrentId('Victor');

        const challenge = {
            credentials: [
                {
                    schema: schema1,
                    issuers: [alice]
                },
                {
                    schema: schema2,
                    issuers: [alice]
                },
                {
                    schema: schema3,
                    issuers: [bob]
                },
                {
                    schema: schema4,
                    issuers: [bob]
                },
            ]
        };
        const challengeDID = await keymaster.createChallenge(challenge, { registry: 'local' });

        await keymaster.setCurrentId('Carol');
        const responseDID = await keymaster.createResponse(challengeDID, { registry: 'local' });
        const { response } = await keymaster.decryptJSON(responseDID) as { response: ChallengeResponse };

        expect(response.challenge).toBe(challengeDID);
        expect(response.credentials.length).toBe(4);

        await keymaster.setCurrentId('Victor');

        const verify1 = await keymaster.verifyResponse(responseDID);
        expect(verify1.match).toBe(true);
        expect(verify1.vps!.length).toBe(4);

        // All agents rotate keys
        await keymaster.setCurrentId('Alice');
        await keymaster.rotateKeys();

        await keymaster.setCurrentId('Bob');
        await keymaster.rotateKeys();

        await keymaster.setCurrentId('Carol');
        await keymaster.rotateKeys();

        await keymaster.setCurrentId('Victor');
        await keymaster.rotateKeys();

        const verify2 = await keymaster.verifyResponse(responseDID);
        expect(verify2.match).toBe(true);
        expect(verify2.vps!.length).toBe(4);

        await keymaster.setCurrentId('Alice');
        await keymaster.revokeCredential(vc1);

        await keymaster.setCurrentId('Victor');
        const verify3 = await keymaster.verifyResponse(responseDID)
        expect(verify3.match).toBe(false);
        expect(verify3.vps!.length).toBe(3);

        await keymaster.setCurrentId('Bob');
        await keymaster.revokeCredential(vc3);

        await keymaster.setCurrentId('Victor');
        const verify4 = await keymaster.verifyResponse(responseDID);
        expect(verify4.match).toBe(false);
        expect(verify4.vps!.length).toBe(2);
    });

    it('should raise exception on invalid parameter', async () => {
        const alice = await keymaster.createId('Alice');

        try {
            // @ts-expect-error Testing invalid usage, missing args
            await keymaster.verifyResponse();
            throw new ExpectedExceptionError();
        }
        catch (error: any) {
            expect(error.message).toBe(InvalidDIDError.type);
        }

        try {
            await keymaster.verifyResponse(alice);
            throw new ExpectedExceptionError();
        }
        catch (error: any) {
            expect(error.message).toBe('Invalid parameter: did not encrypted');
        }

        try {
            await keymaster.verifyResponse('mock');
            throw new ExpectedExceptionError();
        }
        catch (error: any) {
            expect(error.type).toBe(UnknownIDError.type);
        }

        try {
            await keymaster.verifyResponse('did:mock');
            throw new ExpectedExceptionError();
        }
        catch (error: any) {
            expect(error.type).toBe(InvalidDIDError.type);
        }

        try {
            await keymaster.verifyResponse('did:mock', { retries: 10, delay: 10 });
            throw new ExpectedExceptionError();
        }
        catch (error: any) {
            expect(error.type).toBe(InvalidDIDError.type);
        }
    });
});

describe('verifyResponse historical', () => {
    const T0 = '2026-09-01T00:00:00.000Z';
    const at = (minutes: number) => new Date(Date.parse(T0) + minutes * 60_000).toISOString();

    // Fake only the clock so operation timestamps are distinct and known.
    beforeEach(() => {
        jest.useFakeTimers({
            now: new Date(T0),
            doNotFake: ['nextTick', 'setImmediate', 'clearImmediate', 'setInterval', 'clearInterval',
                'setTimeout', 'clearTimeout', 'queueMicrotask', 'hrtime', 'performance'],
        });
    });

    afterEach(() => {
        jest.useRealTimers();
    });

    const setNow = (minutes: number) => jest.setSystemTime(new Date(at(minutes)));

    // Minute 0: Alice issues a credential to Carol. Minute 10: Victor
    // challenges and Carol responds.
    async function respond(credentialOptions = {}) {
        const alice = await keymaster.createId('Alice');
        const carol = await keymaster.createId('Carol');
        await keymaster.createId('Victor');

        await keymaster.setCurrentId('Alice');
        const schema = await keymaster.createSchema(mockSchema);
        const bound = await keymaster.bindCredential(carol, { schema });
        const vc = await keymaster.issueCredential(bound, credentialOptions);

        await keymaster.setCurrentId('Carol');
        await keymaster.acceptCredential(vc);

        setNow(10);
        await keymaster.setCurrentId('Victor');
        const challenge = await keymaster.createChallenge({ credentials: [{ schema, issuers: [alice] }] });

        await keymaster.setCurrentId('Carol');
        const response = await keymaster.createResponse(challenge);
        const { response: { credentials } } = await keymaster.decryptJSON(response) as { response: ChallengeResponse };

        return { alice, carol, schema, vc, vp: credentials[0].vp, challenge, response };
    }

    async function verifyAt(response: string, minutes?: number, versionSequence?: number) {
        await keymaster.setCurrentId('Victor');
        const options = minutes === undefined ? {} : { versionTime: at(minutes), versionSequence };
        return keymaster.verifyResponse(response, options);
    }

    it('verifies before a credential revocation and reflects it afterward', async () => {
        const { carol, vc, response } = await respond();

        setNow(20);
        await keymaster.setCurrentId('Alice');
        await keymaster.revokeCredential(vc);
        setNow(30);

        expect((await verifyAt(response)).match).toBe(false);

        const before = await verifyAt(response, 15);
        expect(before.match).toBe(true);
        expect(before.vps!.length).toBe(1);
        expect(before.responder).toBe(carol);

        const after = await verifyAt(response, 25);
        expect(after.match).toBe(false);
        expect(after.vps!.length).toBe(0);
    });

    it('verifies against the credential content in effect at the cutoff', async () => {
        const { vc, response } = await respond();

        setNow(20);
        await keymaster.setCurrentId('Alice');
        const updated = (await keymaster.getCredential(vc))!;
        updated.credentialSubject!.email = 'updated@email.com';
        await keymaster.updateCredential(vc, updated);

        // The presentation no longer matches the updated credential.
        expect((await verifyAt(response)).match).toBe(false);
        expect((await verifyAt(response, 15)).match).toBe(true);
        expect((await verifyAt(response, 25)).match).toBe(false);
    });

    it('checks the challenge in effect at the cutoff', async () => {
        const { alice, challenge, response } = await respond();

        setNow(20);
        await keymaster.setCurrentId('Alice');
        const extra = await keymaster.createSchema(mockSchema);
        await keymaster.setCurrentId('Victor');
        const { challenge: original } = await keymaster.resolveAsset(challenge);
        await keymaster.mergeData(challenge, {
            challenge: { credentials: [...original.credentials, { schema: extra, issuers: [alice] }] },
        });

        expect((await verifyAt(response)).match).toBe(false);
        expect((await verifyAt(response, 15)).match).toBe(true);
    });

    it('rejects a challenge revoked by the cutoff', async () => {
        const { challenge, response } = await respond();

        setNow(20);
        await keymaster.setCurrentId('Victor');
        await keymaster.revokeDID(challenge);

        await expect(verifyAt(response)).rejects.toThrow('Invalid parameter: challengeDID');
        expect((await verifyAt(response, 15)).match).toBe(true);
        await expect(verifyAt(response, 25)).rejects.toThrow('Invalid parameter: challengeDID');
    });

    it('checks the presentation in effect at the cutoff', async () => {
        const { vp, response } = await respond();

        setNow(20);
        await keymaster.setCurrentId('Carol');
        await keymaster.revokeDID(vp);

        expect((await verifyAt(response)).match).toBe(false);
        expect((await verifyAt(response, 15)).match).toBe(true);
        expect((await verifyAt(response, 25)).match).toBe(false);
    });

    it('selects a response version within the versionTime context', async () => {
        const { challenge, response } = await respond();

        setNow(20);
        await keymaster.setCurrentId('Victor');
        const empty = await keymaster.createChallenge({ credentials: [] });
        await keymaster.setCurrentId('Carol');
        const other = await keymaster.createResponse(empty);
        const { didDocumentData } = await keymaster.resolveDID(other);
        await keymaster.updateDID(response, { didDocumentData });
        setNow(30);

        expect((await verifyAt(response)).challenge).toBe(empty);
        expect((await verifyAt(response, 15)).challenge).toBe(challenge);
        expect((await verifyAt(response, 25)).challenge).toBe(empty);

        const first = await verifyAt(response, 30, 1);
        expect(first.challenge).toBe(challenge);
        expect(first.match).toBe(true);
        expect((await verifyAt(response, 30, 2)).challenge).toBe(empty);

        await expect(verifyAt(response, 15, 2))
            .rejects.toThrow('Invalid parameter: responseDID version 2 is later than versionTime');
        await expect(verifyAt(response, 30, 3))
            .rejects.toThrow('Invalid parameter: responseDID version 3 not found');
    });

    it('refuses cutoffs before the response or its references exist', async () => {
        const { response } = await respond();

        await expect(verifyAt(response, 5))
            .rejects.toThrow('Invalid parameter: responseDID did not exist at versionTime');
        await expect(verifyAt(response, -1))
            .rejects.toThrow('Invalid parameter: responseDID did not exist at versionTime');

        // A response whose challenge was created after the cutoff.
        setNow(20);
        await keymaster.setCurrentId('Victor');
        const later = await keymaster.createChallenge();
        const victor = (await keymaster.fetchIdInfo()).did;
        setNow(10);
        await keymaster.setCurrentId('Carol');
        const forged = await keymaster.encryptJSON({ response: { challenge: later, credentials: [] } }, victor);

        await expect(verifyAt(forged, 15))
            .rejects.toThrow('Invalid parameter: challenge did not exist at versionTime');
    });

    it('rejects malformed selectors', async () => {
        const { response } = await respond();
        await keymaster.setCurrentId('Victor');

        await expect(keymaster.verifyResponse(response, { versionSequence: 1 }))
            .rejects.toThrow('Invalid parameter: versionSequence requires versionTime');
        const malformed = ['yesterday', '0', '01/01/2026', '2026/09/01', '2026-09-01', '2026-09-01T00:15:00',
            '2026-02-29T00:00:00Z', '2026-04-31T00:00:00Z', '2026-09-01T24:00:00Z', '2026-09-01T00:00:60Z',
            '2026-09-01T00:15:00+24:00'];
        for (const versionTime of malformed) {
            await expect(keymaster.verifyResponse(response, { versionTime }))
                .rejects.toThrow('Invalid parameter: versionTime');
        }
        for (const versionTime of ['2026-09-01t00:15:00.123456789z', '2026-09-01T02:15:00+02:00']) {
            expect((await keymaster.verifyResponse(response, { versionTime })).match).toBe(true);
        }
        await expect(keymaster.verifyResponse(response, { versionTime: at(15), versionSequence: 0 }))
            .rejects.toThrow('Invalid parameter: versionSequence');
    });

    it('uses recorded chain evidence for a chain-registered revocation', async () => {
        const registry = 'BTC:signet';
        const { vc, response } = await respond({ registry });

        const anchor = async (height: number, minutes: number) => {
            const events = await db.getEvents(vc);
            const opid = events[events.length - 1].opid!;
            await keymaster.setCurrentId('Alice');
            const batch = await keymaster.createAsset({ batch: { version: 1, ops: [opid] } }, { registry: 'hyperswarm' });
            const time = at(minutes);
            await gatekeeper.addBlock(registry, { height, hash: `block-${height}`, time: Date.parse(time) / 1000 });
            await gatekeeper.importBatchByCids([opid], {
                registry, time, ordinal: [height, 0],
                registration: { height, index: 0, txid: `tx-${height}`, batch },
            });
            await gatekeeper.processEvents();
        };

        await anchor(100, 1);

        setNow(20);
        await keymaster.setCurrentId('Alice');
        await keymaster.revokeCredential(vc);

        // Before the revocation is anchored, its submission time bounds it.
        expect((await verifyAt(response, 15)).match).toBe(true);
        expect((await verifyAt(response, 30)).match).toBe(false);

        // Anchored in a later block, the revocation takes effect at block time.
        setNow(50);
        await anchor(101, 40);

        const doc = await keymaster.resolveDID(vc);
        expect(doc.didDocumentMetadata!.confirmed).toBe(true);
        expect(doc.didDocumentMetadata!.deleted).toBe('2026-09-01T00:40:00Z');
        expect(doc.didDocumentMetadata!.timestamp.upperBound.height).toBe(101);

        expect((await verifyAt(response, 30)).match).toBe(true);
        expect((await verifyAt(response, 39)).match).toBe(true);
        expect((await verifyAt(response, 40)).match).toBe(false);
        expect((await verifyAt(response)).match).toBe(false);

        // The same boundaries hold after a restart replays the stored history.
        gatekeeper = new Gatekeeper({ db, ipfs, registries: ['local', 'hyperswarm', registry] });
        keymaster = new Keymaster({ gatekeeper, wallet, cipher, passphrase: 'passphrase' });
        expect((await verifyAt(response, 39)).match).toBe(true);
        expect((await verifyAt(response, 40)).match).toBe(false);
    });
});
