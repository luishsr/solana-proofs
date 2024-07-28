const Verifier = artifacts.require("Verifier");
const fs = require('fs');
const BN = web3.utils.BN;

contract('Verifier', accounts => {
    it('should verify a proof', async () => {
        const verifier = await Verifier.deployed();

        // Load verification key
        console.log("Loading verification key...");
        const vkRawData = fs.readFileSync('../proofs/verification_key.json');
        console.log("Verification Key Raw Data: ", vkRawData.toString());
        const vkData = JSON.parse(vkRawData);
        console.log("Parsed Verification Key Data: ", vkData);

        // Decode the base58 verification key
        const vkDecoded = web3.utils.hexToBytes(web3.utils.toHex(vkData.verifying_key));
        console.log("Decoded Verification Key: ", vkDecoded);

        // Prepare the verification key parameters
        const alpha = [new BN(vkDecoded.slice(0, 32)), new BN(vkDecoded.slice(32, 64))];
        console.log("Alpha: ", alpha);

        const beta = [
            [new BN(vkDecoded.slice(64, 96)), new BN(vkDecoded.slice(96, 128))],
            [new BN(vkDecoded.slice(128, 160)), new BN(vkDecoded.slice(160, 192))]
        ];
        console.log("Beta: ", beta);

        const gamma = [
            [new BN(vkDecoded.slice(192, 224)), new BN(vkDecoded.slice(224, 256))],
            [new BN(vkDecoded.slice(256, 288)), new BN(vkDecoded.slice(288, 320))]
        ];
        console.log("Gamma: ", gamma);

        const delta = [
            [new BN(vkDecoded.slice(320, 352)), new BN(vkDecoded.slice(352, 384))],
            [new BN(vkDecoded.slice(384, 416)), new BN(vkDecoded.slice(416, 448))]
        ];
        console.log("Delta: ", delta);

        const gamma_abc = [];
        for (let i = 448; i < vkDecoded.length; i += 64) {
            gamma_abc.push([
                new BN(vkDecoded.slice(i, i + 32)),
                new BN(vkDecoded.slice(i + 32, i + 64))
            ]);
        }
        console.log("Gamma ABC: ", gamma_abc);

        // Load proof
        console.log("Loading proof...");
        const proofRawData = fs.readFileSync('../proofs/proof_3CfG5gkkFzLd7avVrZ4Go4vZTKs69pUrQZj2dzbRMoWj2j3s8NeNvA7QqmMiqiruiRaVzifwiaGohWvnMvGWeLKB.json');
        console.log("Proof Raw Data: ", proofRawData.toString());
        const proofData = JSON.parse(proofRawData);
        console.log("Parsed Proof Data: ", proofData);

        // Check if input field exists
        if (!proofData.input) {
            console.error("Error: input field is missing in the proof data.");
            return;
        }

        // Parse proof string
        const proofString = proofData.proof;
        console.log("Proof String: ", proofString);
        const proofRegex = /0x[0-9a-f]+/g;
        const proofHex = proofString.match(proofRegex);
        console.log("Proof Hex Array: ", proofHex);

        // Prepare the proof parameters
        const proof = {
            a: [new BN(proofHex[0], 16), new BN(proofHex[1], 16)],
            b: [
                [new BN(proofHex[2], 16), new BN(proofHex[3], 16)],
                [new BN(proofHex[4], 16), new BN(proofHex[5], 16)]
            ],
            c: [new BN(proofHex[6], 16), new BN(proofHex[7], 16)]
        };
        console.log("Proof: ", proof);

        // Extracting actual inputs from the proof file
        console.log("Extracting actual inputs from the proof file...");
        const input = proofData.input.map(value => new BN(value, 16));
        console.log("Input: ", input);

        // Call the verification function
        console.log("Calling the verification function...");
        const result = await verifier.verifyProof(proof.a, proof.b, proof.c, input);
        console.log("Verification result: ", result);

        assert(result, "Proof verification failed");
    });
});
