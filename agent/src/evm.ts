/**
 * EVM side: derive the guardrail's MPC address for a path, read nonce/fees,
 * and broadcast the raw tx the contract returned. Broadcasting is outside the
 * guardrail by design; the signature is what was gated.
 */
import { JsonRpcProvider, keccak256, getAddress } from "ethers";
import bs58 from "./bs58.js";
import { cfg } from "./config.js";
import { connect, keyStores } from "near-api-js";

/** `derived_public_key(path, predecessor, domain_id)` on the MPC contract -> 0x address. */
export async function derivedAddress(path: string): Promise<string> {
  const near = await connect({ networkId: cfg.network, nodeUrl: cfg.rpcUrl(), keyStore: new keyStores.InMemoryKeyStore() });
  const acc = await near.account(cfg.mpc);
  const pk: string = await acc.viewFunction({
    contractId: cfg.mpc,
    methodName: "derived_public_key",
    args: { path, predecessor: cfg.guardrail(), domain_id: 0 },
  });
  // "secp256k1:<base58 of 64-byte uncompressed point without 04 prefix>"
  const raw = bs58.decode(pk.replace(/^secp256k1:/, ""));
  if (raw.length !== 64) throw new Error(`unexpected derived key length ${raw.length}`);
  const h = keccak256(raw);
  return getAddress("0x" + h.slice(-40));
}

export function provider(): JsonRpcProvider {
  return new JsonRpcProvider(cfg.evmRpc, undefined, { staticNetwork: true });
}

export async function txParams(from: string): Promise<{ nonce: number; maxFeePerGas: bigint; maxPriorityFeePerGas: bigint }> {
  const p = provider();
  const [nonce, fee] = await Promise.all([p.getTransactionCount(from, "pending"), p.getFeeData()]);
  return {
    nonce,
    maxFeePerGas: fee.maxFeePerGas ?? BigInt(1_000_000_000),
    maxPriorityFeePerGas: fee.maxPriorityFeePerGas ?? BigInt(1_000_000),
  };
}

/** Estimate gas for the call from the derived address, +25% headroom. Recipients can be
 *  contracts (incl. EIP-7702 delegated EOAs), so a flat 21000 for "plain transfers" is wrong. */
export async function estimateGas(from: string, to: string, valueWei: bigint, dataB64: string | null): Promise<number> {
  const data = dataB64 ? "0x" + Buffer.from(dataB64, "base64").toString("hex") : "0x";
  const g = await provider().estimateGas({ from, to, value: valueWei, data });
  return Number((g * BigInt(125)) / BigInt(100));
}

export async function broadcast(rawTx: string): Promise<string> {
  const p = provider();
  const r = await p.broadcastTransaction(rawTx);
  return r.hash;
}

/** ABI-encode `transfer(address,uint256)` as base64 for `SignRequest.data`. */
export function erc20TransferCalldata(recipient: string, amount: bigint): string {
  const sel = "a9059cbb";
  const addr = recipient.toLowerCase().replace(/^0x/, "").padStart(64, "0");
  const amt = amount.toString(16).padStart(64, "0");
  return Buffer.from(sel + addr + amt, "hex").toString("base64");
}
