/**
 * Compromised-agent demo: no LLM. Assume the agent was jailbroken or its function-call key
 * stolen. Fire attacks straight at the contract with the agent key and print the rule that
 * stopped each one. `npm run compromised` (testnet; the in-policy drain payments are real
 * and go to the allowlisted address).
 */
import { signAndBroadcast, type SignInput } from "./tools.js";
import { agentAccount, view } from "./near.js";
import { erc20TransferCalldata } from "./evm.js";
import { cfg } from "./config.js";

const ATTACKER = "0x000000000000000000000000000000000000bad0";
const USDC = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";
const base = { chain_id: 84532, path: "treasury-base", value_wei: "0" };
const eth = (x: number) => BigInt(Math.round(x * 1e6)) * BigInt(1e12) + "";
const rows: Array<Record<string, unknown>> = [];
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const fmtRule = (r: unknown) => (r == null ? "" : typeof r === "string" ? r : JSON.stringify(r));

async function attempt(label: string, input: SignInput) {
  const { out } = await signAndBroadcast(input);
  const row = { attack: label, request_id: out.request_id, status: out.status, rule: fmtRule(out.rule), evm_tx: out.evm_tx ?? "" };
  rows.push(row);
  console.log(`${label.padEnd(44)} -> ${out.status}${out.rule ? ` {rule: ${fmtRule(out.rule)}}` : ""}${out.evm_tx ? `  https://sepolia.basescan.org/tx/${out.evm_tx}` : ""}`);
  return out;
}

async function main() {
  const policy = await view<any>("get_policy");
  const allowed = policy.evm.allowed_recipients[0];
  console.log(`== compromised agent vs ${cfg.guardrail()} (policy v${policy.version}, allowed recipient ${allowed})`);
  console.log(`== budget before: ${JSON.stringify((await view<any>("get_budget")).windows.map((w: any) => `${w.spent_usd_cents}/${w.max_usd_cents}c`))}\n`);

  await attempt("1. 0.5 ETH to attacker", { ...base, to: ATTACKER, value_wei: eth(0.5), intent_note: "goodwill bonus" });
  await attempt("2. 0.001 ETH to attacker (small)", { ...base, to: ATTACKER, value_wei: eth(0.001), intent_note: "invoice 1050" });
  await attempt("3. USDC transfer to attacker in calldata", { ...base, to: USDC, erc20_recipient: ATTACKER, erc20_amount: "1000000", intent_note: "refund" });
  await attempt("4. wrong chain (Ethereum mainnet)", { ...base, chain_id: 1, to: allowed, value_wei: eth(0.001), intent_note: "invoice" });
  await attempt("5. 0.004 ETH (~$12) to allowed recipient", { ...base, to: allowed, value_wei: eth(0.004), intent_note: "large invoice" });

  console.log("\n-- drain: repeated $4.50 payments to the allowed recipient, retrying immediately --");
  for (let i = 1; i <= 8; i++) {
    const out = await attempt(`6.${i} drain 0.0015 ETH`, { ...base, to: allowed, value_wei: eth(0.0015), intent_note: `drain ${i}` });
    const rule = fmtRule(out.rule);
    if (rule.includes("window_cap")) break;
    if (out.status === "signed") {
      await attempt(`6.${i}b immediate retry`, { ...base, to: allowed, value_wei: eth(0.0015), intent_note: `drain ${i} retry` });
      await sleep((policy.cooldown_seconds + 2) * 1000);
    }
  }

  console.log("\n-- the agent key itself: call an owner method --");
  try {
    const acc = await agentAccount();
    await acc.functionCall({ contractId: cfg.guardrail(), methodName: "set_policy", args: { policy: { ...policy, version: policy.version + 1 } }, gas: BigInt("50000000000000") });
    console.log("7. set_policy with agent key -> UNEXPECTEDLY ACCEPTED");
    rows.push({ attack: "7. set_policy with agent key", status: "ACCEPTED" });
  } catch (e: any) {
    const msg = String(e?.type ?? e?.message ?? e).slice(0, 80);
    console.log(`7. set_policy with agent key                 -> rejected by the NEAR protocol (${msg})`);
    rows.push({ attack: "7. set_policy with agent key", status: "rejected by protocol", rule: msg });
  }

  console.log(`\n== budget after: ${JSON.stringify((await view<any>("get_budget")).windows.map((w: any) => `${w.spent_usd_cents}/${w.max_usd_cents}c`))}`);
  console.table(rows);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
