/** Print the guardrail's request log, newest first. `npm run tail -- --limit=20` */
import { view } from "./near.js";

type Rec = { id: number; kind: unknown; status: string; rule: unknown; usd_cents: number; created_ns: number; payload_hash: string };

async function main() {
  const limit = Number(process.argv.find((a) => a.startsWith("--limit="))?.split("=")[1] ?? 20);
  const [recs, budget, paused] = await Promise.all([
    view<Rec[]>("get_requests", { before_id: 0, limit }),
    view<any>("get_budget"),
    view<boolean>("is_paused"),
  ]);
  console.log(`paused=${paused}`);
  for (const w of budget.windows) console.log(`window ${w.seconds}s: spent ${w.spent_usd_cents}/${w.max_usd_cents} cents, resets in ${w.resets_in_s}s`);
  console.table(
    recs.map((r) => ({
      id: r.id,
      kind: typeof r.kind === "string" ? r.kind : Object.keys(r.kind as object)[0],
      status: r.status,
      rule: r.rule ? JSON.stringify(r.rule) : "",
      usd_cents: r.usd_cents,
      at: new Date(Number(BigInt(r.created_ns) / BigInt(1_000_000))).toISOString(),
      hash: r.payload_hash.slice(0, 12),
    })),
  );
}
main().catch((e) => {
  console.error(e);
  process.exit(1);
});
