const Verifier = artifacts.require("Verifier");
const fs = require('fs');
const path = require('path');
const Web3 = require('web3');

contract('Verifier', accounts => {
    it('should verify all proofs', async () => {
        const verifier = await Verifier.deployed();

        // Load all files in the proofs directory
        const proofsDir = path.join(__dirname, '../proofs');
        const files = fs.readdirSync(proofsDir);

        // Filter verification key files
        const vkFiles = files.filter(file => file.includes('_vk.json'));
        const proofFiles = files.filter(file => file.includes('proof_') && !file.includes('_vk.json'));

        for (const vkFile of vkFiles) {
            const transactionHash = vkFile.split('_')[1];
            const correspondingProofFile = proofFiles.find(file => file.includes(transactionHash));
            if (!correspondingProofFile) {
                console.log(`No corresponding proof file found for ${vkFile}`);
                continue;
            }

            console.log(`Verifying proof for transaction hash: ${transactionHash}`);

            // Load verification key
            console.log("Loading verification key...");
            const vkRawData = fs.readFileSync(path.join(proofsDir, vkFile));
            console.log("Verification Key Raw Data: ", vkRawData.toString());
            const vkData = JSON.parse(vkRawData);
            console.log("Parsed Verification Key Data: ", vkData);

            // Decode the base58 verification key
            const vkDecoded = web3.utils.hexToBytes(web3.utils.toHex(vkData.verifying_key));
            console.log("Decoded Verification Key: ", vkDecoded);

            // Prepare the verification key parameters
            const alpha = [new web3.utils.BN(vkDecoded.slice(0, 32)), new web3.utils.BN(vkDecoded.slice(32, 64))];
            console.log("Alpha: ", alpha);

            const beta = [
                [new web3.utils.BN(vkDecoded.slice(64, 96)), new web3.utils.BN(vkDecoded.slice(96, 128))],
                [new web3.utils.BN(vkDecoded.slice(128, 160)), new web3.utils.BN(vkDecoded.slice(160, 192))]
            ];
            console.log("Beta: ", beta);

            const gamma = [
                [new web3.utils.BN(vkDecoded.slice(192, 224)), new web3.utils.BN(vkDecoded.slice(224, 256))],
                [new web3.utils.BN(vkDecoded.slice(256, 288)), new web3.utils.BN(vkDecoded.slice(288, 320))]
            ];
            console.log("Gamma: ", gamma);

            const delta = [
                [new web3.utils.BN(vkDecoded.slice(320, 352)), new web3.utils.BN(vkDecoded.slice(352, 384))],
                [new web3.utils.BN(vkDecoded.slice(384, 416)), new web3.utils.BN(vkDecoded.slice(416, 448))]
            ];
            console.log("Delta: ", delta);

            const gamma_abc = [];
            for (let i = 448; i < vkDecoded.length; i += 64) {
                gamma_abc.push([
                    new web3.utils.BN(vkDecoded.slice(i, i + 32)),
                    new web3.utils.BN(vkDecoded.slice(i + 32, i + 64))
                ]);
            }
            console.log("Gamma ABC: ", gamma_abc);

            // Load proof
            console.log("Loading proof...");
            const proofRawData = fs.readFileSync(path.join(proofsDir, correspondingProofFile));
            console.log("Proof Raw Data: ", proofRawData.toString());
            const proofData = JSON.parse(proofRawData);
            console.log("Parsed Proof Data: ", proofData);

            // Check if input field exists
            if (!proofData.input) {
                console.error("Error: input field is missing in the proof data.");
                return;
            }

            // Validate proof data size
            const validateSize = (bnArray, maxSize) => {
                return bnArray.every(bn => bn.byteLength() <= maxSize);
            };

            const maxSize = 32; // 32 bytes = 256 bits

            const proof = {
                a: [new web3.utils.BN(proofData.proof.a[0], 16), new web3.utils.BN(proofData.proof.a[1], 16)],
                b: [
                    [new web3.utils.BN(proofData.proof.b[0][0], 16), new web3.utils.BN(proofData.proof.b[0][1], 16)],
                    [new web3.utils.BN(proofData.proof.b[1][0], 16), new web3.utils.BN(proofData.proof.b[1][1], 16)]
                ],
                c: [new web3.utils.BN(proofData.proof.c[0], 16), new web3.utils.BN(proofData.proof.c[1], 16)]
            };

            // Check if any proof parameter exceeds the max size
            if (!validateSize(proof.a, maxSize) || !validateSize(proof.b.flat(), maxSize) || !validateSize(proof.c, maxSize)) {
                console.error("Error: Proof parameters exceed maximum allowed size.");
                console.log("Proof 'a' sizes:", proof.a.map(p => p.byteLength()));
                console.log("Proof 'b' sizes:", proof.b.flat().map(p => p.byteLength()));
                console.log("Proof 'c' sizes:", proof.c.map(p => p.byteLength()));
                return;
            }

            console.log("Proof: ", proof);

            // Extracting actual inputs from the proof file
            console.log("Extracting actual inputs from the proof file...");
            const input = proofData.input.map(value => new web3.utils.BN(value, 16));
            console.log("Input: ", input);

            if (!validateSize(input, maxSize)) {
                console.error("Error: Input parameters exceed maximum allowed size.");
                console.log("Input sizes:", input.map(p => p.byteLength()));
                return;
            }

            // Call the verification function
            console.log("Calling the verification function...");
            const result = await verifier.verifyProof(proof.a, proof.b, proof.c, input);
            console.log("Verification result: ", result);

            assert(result, "Proof verification failed");
        }
    });
});
