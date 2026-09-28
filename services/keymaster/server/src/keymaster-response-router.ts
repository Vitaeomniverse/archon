import express from 'express';
import type { CreateKeymasterRouterOptions } from './keymaster-router-types.js';
import { sendError } from './keymaster-error-status.js';

export function createResponseRouter(options: CreateKeymasterRouterOptions): express.Router {
    const { getKeymaster } = options;
    const router = express.Router();

    /**
     * @swagger
     * /response:
     *   post:
     *     summary: Create a response to an existing challenge DID.
     *     description: >
     *       Accepts a challenge DID (the DID of a previously created challenge) and an `options` object, then returns a new DID containing the
     *       response. Internally, the Keymaster finds matching credentials and bundles them into verifiable presentations. The response is
     *       encrypted for the original challenge's controller and stored as a new asset DID.
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             properties:
     *               challenge:
     *                 type: string
     *                 description: DID of the challenge to respond to.
     *               options:
     *                 type: object
     *                 description: Additional parameters controlling how the response is created and stored.
     *                 properties:
     *                   registry:
     *                     type: string
     *                     description: The registry where the new response DID will be created (e.g., "local", "hyperswarm").
     *                   validUntil:
     *                     type: string
     *                     format: date-time
     *                     description: Expiration time for the response DID. If omitted, defaults to 1 hour from now.
     *                   retries:
     *                     type: integer
     *                     description: How many times to retry resolving the challenge DID if it is not immediately resolvable.
     *                     default: 0
     *                   delay:
     *                     type: integer
     *                     description: Milliseconds to wait between retries.
     *                     default: 1000
     *                   encryptForSender:
     *                     type: boolean
     *                     description: Whether to include an encrypted copy for the sender (the responding party). Defaults to true.
     *                   includeHash:
     *                     type: boolean
     *                     description: Whether to embed a hash of the plaintext in the stored asset. Defaults to false.
     *                   controller:
     *                     type: string
     *                     description: A specific ID or DID to act as the controller of the newly created asset. If not set, the current ID is used.
     *     responses:
     *       200:
     *         description: A DID containing the response to the challenge.
     *         content:
     *           application/json:
     *             schema:
     *               type: object
     *               properties:
     *                 did:
     *                   type: string
     *                   description: The DID of the newly created response asset.
     *       400:
     *         description: Invalid input (e.g., challenge not found, or required parameters missing).
     *         content:
     *           application/json:
     *             schema:
     *               type: object
     *               properties:
     *                 error:
     *                   type: string
     *       500:
     *         description: Internal server error.
     *         content:
     *           application/json:
     *             schema:
     *               type: object
     *               properties:
     *                 error:
     *                   type: string
     */
    router.post('/response', async (req, res) => {
        try {
            const { challenge, options } = req.body;
            const did = await getKeymaster().createResponse(challenge, options);
            res.json({ did });
        } catch (error: any) {
            sendError(res, error);
        }
    });

    /**
     * @swagger
     * /response/verify:
     *   post:
     *     summary: Verify a response to a challenge.
     *     description: >
     *       Without `versionTime`, verifies against the current state of every DID involved. With it, verifies the response
     *       as it stood at that time, so a response checked after a credential revocation can still be audited as of an
     *       earlier point.
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             properties:
     *               response:
     *                 type: string
     *                 description: DID of the challenge response asset to verify.
     *               options:
     *                 type: object
     *                 description: Additional verification parameters.
     *                 properties:
     *                   retries:
     *                     type: integer
     *                     description: How many times to retry resolving the response DID if initially not found.
     *                     default: 0
     *                   delay:
     *                     type: integer
     *                     description: How many milliseconds to wait between resolution retries.
     *                     default: 1000
     *                   versionTime:
     *                     type: string
     *                     format: date-time
     *                     description: >
     *                       RFC 3339 date-time with an offset. Verify in the context of this time. The response, challenge, credential, and presentation DIDs,
     *                       including the documents decrypted during verification, are resolved as of this time. A DID that
     *                       did not exist by then is an error rather than a fallback to its current state. Proof keys keep
     *                       their existing selection: each signer is resolved at its proof's `created` time. The time
     *                       describes the verification context; it is not by itself evidence that an external action
     *                       happened then.
     *                   versionSequence:
     *                     type: integer
     *                     minimum: 1
     *                     description: >
     *                       Verify this version of the response DID. Requires `versionTime`, which must not precede the
     *                       selected version and still selects the context of the DIDs the response references. A version
     *                       the response does not have is an error.
     *     responses:
     *       200:
     *         description: The result of the verification process.
     *         content:
     *           application/json:
     *             schema:
     *               type: object
     *               properties:
     *                 verify:
     *                   type: object
     *                   description: A detailed verification result.
     *                   properties:
     *                     challenge:
     *                       type: string
     *                       description: The DID of the original challenge.
     *                     credentials:
     *                       type: array
     *                       items:
     *                         type: object
     *                       description: Each credential pair (vc, vp) the response included.
     *                     match:
     *                       type: boolean
     *                       description: true if the response satisfies all challenge requirements, otherwise `false`.
     *                     vps:
     *                       type: array
     *                       description: Any verifiable presentations that passed verification.
     *                       items:
     *                         type: object
     *                     responder:
     *                       type: string
     *                       description: The DID (controller) of the responder.
     *       400:
     *         description: Verification failed or request was invalid.
     *         content:
     *           application/json:
     *             schema:
     *               type: object
     *               properties:
     *                 error:
     *                   type: string
     *       500:
     *         description: Internal server error.
     *         content:
     *           application/json:
     *             schema:
     *               type: object
     *               properties:
     *                 error:
     *                   type: string
     */
    router.post('/response/verify', async (req, res) => {
        try {
            const { response, options } = req.body;
            const verify = await getKeymaster().verifyResponse(response, options);
            res.json({ verify });
        } catch (error: any) {
            sendError(res, error);
        }
    });


    return router;
}
