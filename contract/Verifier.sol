// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Verifier.sol"; // Assuming the Verifier.sol from zk-SNARK precompiled contracts

contract ProofVerifier {
    Verifier verifier;
    address verifierAddress;

    constructor(address _verifierAddress) {
        verifierAddress = _verifierAddress;
        verifier = Verifier(_verifierAddress);
    }

    function verifyProof(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[1] memory input
    ) public view returns (bool) {
        return verifier.verifyProof(a, b, c, input);
    }
}
