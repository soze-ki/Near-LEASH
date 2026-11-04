/**
 * Thin NEAR layer. The agent only ever holds a function-call key scoped to
 * `request_sign,request_swap` on the guardrail account; everything else here
 * is owner tooling used by the deploy script and the demo harness.
 */
import { connect, keyStores, KeyPair, Account, Near } from "near-api-js";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { cfg } from "./config.js";

export type RequestOutcome = {
  request_id: number;
  status: string;
  rule: string | { window_cap: { index: number } } | null;
  signature: { r: string; s: string; recovery_id: number } | null;
  raw_tx: string | null;
  deposit_address: string | null;
};

/** near-api-js prints every receipt and retry; hidden unless NEAR_LOGS=1 (cleaner for demos). */
const quiet = process.env.NEAR_LOGS === "1" ? {} : { logger: false as const };

export const GAS_300 = BigInt("300000000000000");
export const GAS_50 = BigInt("50000000000000");

async function nearWith(accountId: string, key: string): Promise<Near> {
  const keyStore = new keyStores.InMemoryKeyStore();
  await keyStore.setKey(cfg.network, accountId, KeyPair.fromString(key as any));
  return connect({ networkId: cfg.network, nodeUrl: cfg.rpcUrl(), keyStore, ...quiet });
}

/** The agent: signs as the guardrail account with its restricted key. */
export async function agentAccount(): Promise<Account> {
  const near = await nearWith(cfg.guardrail(), cfg.agentKey());
  return near.account(cfg.guardrail());
}

/** Owner key from ~/.near-credentials/<network>/<owner>.json (near-cli format). */
export function ownerKeyFromCredentials(accountId: string): string {
  const f = join(homedir(), ".near-credentials", cfg.network, `${accountId}.json`);
  const j = JSON.parse(readFileSync(f, "utf8"));
  return j.private_key ?? j.secret_key;
}

export async function ownerAccount(): Promise<Account> {
  const owner = cfg.owner();
  const near = await nearWith(owner, ownerKeyFromCredentials(owner));
  return near.account(owner);
}

export async function accountWithKey(accountId: string, key: string): Promise<Account> {
  const near = await nearWith(accountId, key);
  return near.account(accountId);
}

export async function view<T>(method: string, args: Record<string, unknown> = {}): Promise<T> {
  const near = await connect({ networkId: cfg.network, nodeUrl: cfg.rpcUrl(), keyStore: new keyStores.InMemoryKeyStore(), ...quiet });
  const acc = await near.account(cfg.guardrail());
  return acc.viewFunction({ contractId: cfg.guardrail(), methodName: method, args }) as Promise<T>;
}

/** Call a guardrail method and return the parsed result plus the NEP-297 events it logged. */
export async function call<T>(
  account: Account,
  method: string,
  args: Record<string, unknown>,
  gas: bigint = GAS_300,
): Promise<{ result: T; events: Array<{ event: string; data: Record<string, unknown> }>; txHash: string }> {
  const r = await account.functionCall({ contractId: cfg.guardrail(), methodName: method, args, gas, attachedDeposit: BigInt(0) });
  const logs: string[] = [];
  for (const o of [r.transaction_outcome, ...r.receipts_outcome]) logs.push(...(o.outcome.logs ?? []));
  const events = logs
    .filter((l) => l.startsWith("EVENT_JSON:"))
    .map((l) => JSON.parse(l.slice("EVENT_JSON:".length)))
    .map((e) => ({ event: e.event as string, data: e.data[0] as Record<string, unknown> }));
  const status = r.status as { SuccessValue?: string };
  const result = status.SuccessValue ? (JSON.parse(Buffer.from(status.SuccessValue, "base64").toString()) as T) : (null as T);
  return { result, events, txHash: r.transaction.hash as string };
}
