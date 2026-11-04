/**
 * Rebuild a signed request's raw tx from the on-chain record and broadcast it.
 * `npm run rebroadcast -- <request_id>` — for a request that was signed but whose
 * broadcast failed (e.g. the derived address was not funded yet). Spends no budget.
 */
import { Transaction, Signature } from "ethers";
import { view } from "./near.js";
import { broadcast, provider } from "./evm.js";

const id = Number(process.argv[2]);
if (!id) throw new Error("usage: npm run rebroadcast -- <request_id>");
const rec = await view<any>("get_request", { request_id: id });
if (!rec || rec.status !== "signed") throw new Error(`request ${id} is ${rec?.status ?? "missing"}, not signed`);
const q = rec.kind.Sign, sig = JSON.parse(rec.result);
const tx = Transaction.from({
  type: 2, chainId: q.chain_id, nonce: q.nonce, to: q.to, value: BigInt(q.value),
  data: q.data ? "0x" + Buffer.from(q.data, "base64").toString("hex") : "0x",
  gasLimit: q.gas_limit, maxFeePerGas: BigInt(q.max_fee_per_gas), maxPriorityFeePerGas: BigInt(q.max_priority_fee_per_gas),
});
if (tx.unsignedHash.slice(2) !== rec.payload_hash) throw new Error("rebuilt hash does not match the hash the contract signed");
tx.signature = Signature.from({ r: "0x" + sig.r, s: "0x" + sig.s, v: 27 + sig.recovery_id });
const bal = await provider().getBalance(tx.from!);
console.log(`request ${id}: from ${tx.from} (balance ${bal} wei) nonce ${q.nonce} to ${q.to} value ${q.value}`);
const need = BigInt(q.value) + BigInt(q.gas_limit) * BigInt(q.max_fee_per_gas);
if (bal < need) {
  console.error(`not funded: ${tx.from} needs at least ${need} wei (value + max gas). Send Base Sepolia ETH to it, then rerun.`);
  process.exit(1);
}
const hash = await broadcast(tx.serialized);
console.log(`broadcast: https://sepolia.basescan.org/tx/${hash}`);
