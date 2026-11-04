/** 1Click quote fetch. Mainnet only (no Intents testnet exists). */
import { cfg } from "./config.js";

export type QuoteResponse = {
  timestamp: string;
  signature: string;
  quoteRequest: Record<string, unknown>;
  quote: Record<string, unknown>;
};

export async function getQuote(req: {
  originAsset: string;
  destinationAsset: string;
  amount: string;
  recipient: string;
  slippageTolerance?: number;
  dry?: boolean;
}): Promise<QuoteResponse> {
  const body = {
    dry: req.dry ?? false,
    swapType: "EXACT_INPUT",
    slippageTolerance: req.slippageTolerance ?? 100,
    originAsset: req.originAsset,
    depositType: "ORIGIN_CHAIN",
    destinationAsset: req.destinationAsset,
    amount: req.amount,
    refundTo: cfg.guardrail(), // policy forces refund_to == guardrail; set it honestly here
    refundType: "ORIGIN_CHAIN",
    recipient: req.recipient,
    recipientType: "DESTINATION_CHAIN",
    deadline: new Date(Date.now() + 10 * 60_000).toISOString(),
  };
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (cfg.oneclickJwt) headers.authorization = `Bearer ${cfg.oneclickJwt}`;
  const r = await fetch(`${cfg.oneclickUrl}/v0/quote`, { method: "POST", headers, body: JSON.stringify(body) });
  if (!r.ok) throw new Error(`1click ${r.status}: ${await r.text()}`);
  return (await r.json()) as QuoteResponse;
}

export async function getStatus(depositAddress: string): Promise<unknown> {
  const r = await fetch(`${cfg.oneclickUrl}/v0/status?depositAddress=${encodeURIComponent(depositAddress)}`);
  return r.json();
}
