import { readFileSync } from 'node:fs';
import Keymaster from '@didcid/keymaster';
import CipherNode from '@didcid/cipher/node';
import WalletJsonMemory from '@didcid/keymaster/wallet/json-memory';

// Responses created by the Python keymaster, verified here by the TypeScript
// one from the documents a real Gatekeeper resolved for them. The Python suite
// verifies the opposite direction from the same fixture, which
// tests/keymaster/generate-response-interop-vectors.mjs produces (#1300).
const fixture = JSON.parse(readFileSync('tests/fixtures/response-interop.json', 'utf-8'));
const direction = fixture.pythonToTypescript;

function fixtureGatekeeper(documents: Record<string, any>) {
    return {
        async resolveDID(did: string) {
            return documents[did]
                ? structuredClone(documents[did])
                : { didResolutionMetadata: { error: 'notFound' }, didDocument: {}, didDocumentMetadata: {} };
        },
        async listRegistries() {
            return ['local', 'hyperswarm'];
        },
        // Verification only reads; a write here would be a defect.
        async createDID(): Promise<string> {
            throw new Error('fixture Gatekeeper is read-only');
        },
    };
}

let keymaster: Keymaster;

beforeEach(async () => {
    const wallet = new WalletJsonMemory();
    await wallet.saveWallet(structuredClone(direction.verifier.wallet), true);
    keymaster = new Keymaster({
        gatekeeper: fixtureGatekeeper(direction.documents) as any,
        wallet,
        cipher: new CipherNode(),
        passphrase: fixture.passphrase,
    });
    await keymaster.setCurrentId(direction.verifier.name);
});

describe('Python responses verified by TypeScript', () => {
    it('present each credential through its own presentation DID', async () => {
        for (const response of Object.values(direction.responses) as string[]) {
            const { response: { credentials } } = await keymaster.decryptJSON(response) as any;
            expect(credentials.length).toBe(1);
            expect(credentials[0].vc).toMatch(/^did:cid:/);
            expect(credentials[0].vp).toMatch(/^did:cid:/);
        }
    });

    it.each(['valid', 'revoked'])('verifies the %s response as the Python verifier did', async label => {
        const verified = await keymaster.verifyResponse(direction.responses[label]);
        const vps = (verified.vps ?? []) as any[];

        expect({
            match: verified.match,
            issuers: vps.map(vp => vp.issuer),
            subjects: vps.map(vp => vp.credentialSubject?.id),
        }).toEqual(direction.expected[label]);
    });
});
