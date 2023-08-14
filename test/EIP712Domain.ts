import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { ethers } from "hardhat";
import { expect } from "chai";
import Web3 from 'web3';
import "dotenv/config";

describe("EIP712 Domain Test", function (): void {
    async function deployEIP712DomainTest() {
        const [owner, otherAccount] = await ethers.getSigners();
        const Contract = await ethers.getContractFactory("TransferOrder");
        const contract = await Contract.deploy("EIP712 Domain", "1");
        return { owner, otherAccount, contract };
    }

    it("Should verify digital signature successful", async function (): Promise<void> {
        const { contract, otherAccount } = await loadFixture(deployEIP712DomainTest);
        const web3 = new Web3(process.env.ALCHEMY_RPC_URL!);
        const privateKey = process.env.PRIVATE_KEY!
        const publicKey = new ethers.Wallet(privateKey);
        const hashes = await contract.getTransferHash(
            otherAccount.address,
            1,
            "0x626c756500000000000000000000000000000000000000000000000000000000",
            1690815265
        )
        const signature = web3.eth.accounts.sign(hashes, `0x${privateKey}`);
        const recoveredAddress = await contract.verify(
            signature.messageHash,
            signature.signature,
            publicKey.address
        )
        expect(publicKey.address).to.be.equal(recoveredAddress);
    })
})
