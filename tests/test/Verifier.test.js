const Verifier = artifacts.require("Verifier");
const fs = require('fs');

contract('Verifier', accounts => {
    it('should verify a proof', async () => {
        const verifier = await Verifier.deployed();

        // Load verification key
        const vkData = JSON.parse(fs.readFileSync('../proofs/verification_key.json'));

        // Mock proof (replace with actual proof data)
        const proof = {
            a: ["0x0616d841276544bdc1d8fd53e34373f9adc3ac8dd06c54be132ba2a1fcda5e65", "0x16c0a6cf977cd9277f6c38e5725196f205bfaaf3c222631014f4d26cb23bd572"],
            b: [["0x02beb4b754f8536db37009ec391ccff9ec1787a3f56289abf8340257ca1932ed", "0x17eb67eb25c8f8b86af5c5a2c25f371919f2762c03ca7f23b42bcfc9cc5a4bca"], ["0x0a3f6855e80a83d29df8465e18fe8d073ab38c61e70c9efdb0151f5bc8a9fc50", "0x16db56b13e6db468b2d3d3042e62747ff8fc24d3ddaa9ccd376f89c224681507"]],
            c: ["0x0259b9f645a599ccdd66b7ca1c81fe3386dd2abc70c6288ebfbcf65afaecf7f3", "0x06827834987af1293f9def4e0ef1ee3e63ed58c1749f7286df616c055b225b35"]
        };

        // Prepare the inputs for the contract function
        const input = [/* Your inputs here */];
        const alpha = [vkData.alpha.x, vkData.alpha.y];
        const beta = [[vkData.beta.x[0], vkData.beta.x[1]], [vkData.beta.y[0], vkData.beta.y[1]]];
        const gamma = [[vkData.gamma.x[0], vkData.gamma.x[1]], [vkData.gamma.y[0], vkData.gamma.y[1]]];
        const delta = [[vkData.delta.x[0], vkData.delta.x[1]], [vkData.delta.y[0], vkData.delta.y[1]]];
        const gamma_abc = vkData.gamma_abc.map(point => [point.x, point.y]);

        // Call the verification function
        const result = await verifier.verify_proof(input, proof.a, proof.b, proof.c, alpha, beta, gamma, delta, gamma_abc);
        assert(result, "Proof verification failed");
    });
});
