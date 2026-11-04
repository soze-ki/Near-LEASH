/**
 * The five tools the model can call. Every spend goes through the guardrail
 * contract; the model never sees a key and cannot bypass the policy. Tool
 * results are returned verbatim including the denial `rule`, so the model
 * (and the demo log) always know *why* something was refused.
 */
import { betaZodTool } from "@anthropic-ai/sdk/helpers/beta/zod";
import { z } from "zod";
import { agentAccount, call, view, type RequestOutcome } from "./near.js";
import { broadcast, derivedAddress, erc20TransferCalldata, estimateGas, txParams } from "./evm.js";
import { getQuote, type QuoteResponse } from "./oneclick.js";
import { cfg } from "./config.js";

export type ToolLog = { tool: string; input: unknown; output: unknown; events: unknown[] };
export const toolLog: ToolLog[] = [];
function record(entry: ToolLog) {
  toolLog.push(entry);
  const ev = entry.events.map((e: any) => `${e.event}${e.data?.rule ? `{rule:${JSON.stringify(e.data.rule)}}` : ""}`).join(", ");
  console.log(`  [tool] ${entry.tool} -> ${JSON.stringify(entry.output).slice(0, 160)}${ev ? `  events: ${ev}` : ""}`);
}

export const readPolicy = betaZodTool({
  name: "read_policy",
  description: "Read the owner-set spending policy of the guardrail contract (allowed recipients, chains, tokens, caps).",
  inputSchema: z.object({}),
  run: async () => {
    const out = await view("get_policy");
    record({ tool: "read_policy", input: {}, output: out, events: [] });
    return JSON.stringify(out);
  },
});

export const getBudget = betaZodTool({
  name: "get_budget",
  description: "Read remaining budget per window and cooldown.",
  inputSchema: z.object({}),
  run: async () => {
    const out = await view("get_budget");
    record({ tool: "get_budget", input: {}, output: out, events: [] });
    return JSON.stringify(out);
  },
});

export type SignInput = { chain_id: number; to: string; value_wei: string; erc20_recipient?: string; erc20_amount?: string; path: string; intent_note: string };

/** Build a SignRequest, submit it with the agent key, broadcast if signed. Shared by the LLM tool and the compromised-agent script. */
export async function signAndBroadcast(input: SignInput) {
    const from = await derivedAddress(input.path);
    const p = await txParams(from);
    const data = input.erc20_recipient && input.erc20_amount ? erc20TransferCalldata(input.erc20_recipient, BigInt(input.erc20_amount)) : null;
    const req = {
      chain_id: input.chain_id,
      to: input.to,
      value: input.value_wei,
      data,
      nonce: p.nonce,
      gas_limit: await estimateGas(from, input.to, BigInt(input.value_wei), data).catch(() => (data ? 80_000 : 21_000)),
      max_fee_per_gas: p.maxFeePerGas.toString(),
      max_priority_fee_per_gas: p.maxPriorityFeePerGas.toString(),
      path: input.path,
      intent_note: input.intent_note,
    };
    const acc = await agentAccount();
    const { result, events, txHash } = await call<RequestOutcome>(acc, "request_sign", { req });
    let evm_tx: string | null = null;
    let broadcast_error: string | null = null;
    if (result?.status === "signed" && result.raw_tx) {
      try {
        evm_tx = await broadcast(result.raw_tx);
      } catch (e: any) {
        broadcast_error = String(e?.shortMessage ?? e?.message ?? e);
      }
    }
    const out = { ...result, near_tx: txHash, from, evm_tx, broadcast_error };
    return { out, events };
}

export const requestSign = betaZodTool({
  name: "request_sign",
  description:
    "Ask the guardrail to build, policy-check and MPC-sign an EVM transaction, then broadcast it. " +
    "Native transfer: set `to` and `value_wei`. ERC-20 transfer: set `to` = token contract, `erc20_recipient` and `erc20_amount` (raw units). " +
    "Returns the outcome: status signed|denied|parked and the `rule` on denial.",
  inputSchema: z.object({
    chain_id: z.number().int().default(84532),
    to: z.string().describe("0x address: recipient for native, token contract for ERC-20"),
    value_wei: z.string().default("0"),
    erc20_recipient: z.string().optional(),
    erc20_amount: z.string().optional().describe("raw token units, e.g. 12000000 for 12 USDC"),
    path: z.string().default("treasury-base"),
    intent_note: z.string().describe("one line on why; logged on-chain, not trusted"),
  }),
  run: async (input) => {
    const { out, events } = await signAndBroadcast(input);
    record({ tool: "request_sign", input, output: out, events });
    return JSON.stringify(out);
  },
});

export const getQuoteTool = betaZodTool({
  name: "get_quote",
  description: "Get a signed 1Click (NEAR Intents) swap quote. Mainnet only. Pass the quote object to request_swap unchanged.",
  inputSchema: z.object({
    origin_asset: z.string(),
    destination_asset: z.string(),
    amount: z.string().describe("raw units of origin asset"),
    recipient: z.string(),
  }),
  run: async (input) => {
    const q = await getQuote({ originAsset: input.origin_asset, destinationAsset: input.destination_asset, amount: input.amount, recipient: input.recipient });
    record({ tool: "get_quote", input, output: { depositAddress: q.quote.depositAddress, amountOut: q.quote.amountOut, amountInUsd: q.quote.amountInUsd }, events: [] });
    return JSON.stringify(q);
  },
});

export const requestSwap = betaZodTool({
  name: "request_swap",
  description: "Submit a 1Click quote to the guardrail. It verifies the quote signature and policy, then funds the deposit address from the treasury.",
  inputSchema: z.object({ quote: z.any().describe("the full QuoteResponse from get_quote") }),
  run: async (input) => {
    const acc = await agentAccount();
    const { result, events, txHash } = await call<RequestOutcome>(acc, "request_swap", { quote: input.quote as QuoteResponse });
    const out = { ...result, near_tx: txHash };
    record({ tool: "request_swap", input: { depositAddress: (input.quote as any)?.quote?.depositAddress }, output: out, events });
    return JSON.stringify(out);
  },
});

export const tools = [readPolicy, getBudget, requestSign, getQuoteTool, requestSwap];
export const guardrailId = () => cfg.guardrail();
