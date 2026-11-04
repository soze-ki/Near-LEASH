/**
 * Replace the on-chain policy as the owner. `npm run set-policy [-- --policy=path.json]`
 * The version must be higher than the live one. Spend counters survive unless the
 * window layout changes (the event says budget_reset).
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { AGENT_DIR } from "./config.js";
import { ownerAccount, call, view, GAS_50 } from "./near.js";

const file = process.argv.find((a) => a.startsWith("--policy="))?.split("=")[1] ?? join(AGENT_DIR, "policies/testnet.json");
const policy = JSON.parse(readFileSync(file, "utf8"));
const live = await view<{ version: number }>("get_policy");
console.log(`live version ${live.version}, applying version ${policy.version} from ${file}`);
if (policy.version <= live.version) throw new Error("bump `version` in the policy file first");
const owner = await ownerAccount();
const r = await call(owner, "set_policy", { policy }, GAS_50);
console.log("events:", JSON.stringify(r.events), "tx:", r.txHash);
const now = await view<any>("get_policy");
console.log("now live: version", now.version, "evm recipients", now.evm.allowed_recipients);
