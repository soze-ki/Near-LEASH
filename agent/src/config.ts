import "dotenv/config";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
export const AGENT_DIR = join(here, "..");
export const REPO_DIR = join(AGENT_DIR, "..");

function req(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`missing env ${name} (see agent/.env.example)`);
  return v;
}

export const cfg = {
  network: process.env.NEAR_NETWORK ?? "testnet",
  owner: () => req("OWNER_ACCOUNT"),
  guardrail: () => req("GUARDRAIL_ACCOUNT"),
  mpc: process.env.MPC_ACCOUNT ?? "v1.signer-prod.testnet",
  evmRpc: process.env.EVM_RPC_URL ?? "https://sepolia.base.org",
  oneclickUrl: process.env.ONECLICK_URL ?? "https://1click.chaindefuser.com",
  oneclickJwt: process.env.ONECLICK_JWT ?? "",
  rpcUrl: () => process.env.NEAR_RPC_URL ?? `https://rpc.${process.env.NEAR_NETWORK ?? "testnet"}.near.org`,
  /** Agent function-call key: env wins, else the file deploy wrote. */
  agentKey: (): string => {
    if (process.env.AGENT_PRIVATE_KEY) return process.env.AGENT_PRIVATE_KEY;
    const f = join(AGENT_DIR, ".agent-key.json");
    if (!existsSync(f)) throw new Error("no AGENT_PRIVATE_KEY and no agent/.agent-key.json; run `npm run deploy` first");
    return JSON.parse(readFileSync(f, "utf8")).private_key as string;
  },
};
