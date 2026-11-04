/**
 * Testnet deploy, run by the human with the owner key in ~/.near-credentials.
 *
 *   npm run deploy                      # create guardrail.<owner>, deploy, init, add agent key, drop FA key
 *   npm run deploy -- --policy=path.json
 *   npm run deploy -- --keep-fa-key     # keep the deploy key (debugging only)
 *
 * Writes agent/.agent-key.json (gitignored). Saves the temporary deploy key to
 * agent/.deploy-key.<account>.json before creating the account, so a failed run resumes.
 */
import { existsSync, readFileSync, writeFileSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { KeyPair, utils } from "near-api-js";
import { AGENT_DIR, REPO_DIR, cfg } from "./config.js";
import { ownerAccount, accountWithKey, call, GAS_50 } from "./near.js";

const WASM = join(REPO_DIR, "target/wasm32-unknown-unknown/release/guardrail.wasm");

async function main() {
  const owner = await ownerAccount();
  const contractId = cfg.guardrail();
  if (!contractId.endsWith(`.${cfg.owner()}`)) throw new Error("GUARDRAIL_ACCOUNT must be a sub-account of OWNER_ACCOUNT");
  const policyFile = process.argv.find((a) => a.startsWith("--policy="))?.split("=")[1] ?? join(AGENT_DIR, "policies/testnet.json");
  const policy = JSON.parse(readFileSync(policyFile, "utf8"));
  const wasm = readFileSync(WASM);
  console.log(`owner=${owner.accountId} contract=${contractId} wasm=${wasm.length} bytes policy=${policyFile}`);

  // 1. create sub-account with a temporary full-access deploy key. The key is saved
  //    BEFORE the account is created, so a failed deploy can be resumed instead of
  //    leaving an account nobody holds a key for.
  const deployKeyFile = join(AGENT_DIR, `.deploy-key.${contractId}.json`);
  let deployKey: KeyPair;
  if (existsSync(deployKeyFile)) {
    deployKey = KeyPair.fromString(JSON.parse(readFileSync(deployKeyFile, "utf8")).private_key);
    console.log("resuming with saved deploy key", deployKeyFile);
  } else {
    deployKey = KeyPair.fromRandom("ed25519");
    writeFileSync(deployKeyFile, JSON.stringify({ account_id: contractId, private_key: deployKey.toString() }), { mode: 0o600 });
  }
  const contract = await accountWithKey(contractId, deployKey.toString());
  const exists = await contract.state().then(() => true, () => false);
  // storage: 1 NEAR per 100 kB of code, + 1.5 NEAR for state, gas and the agent key's allowance
  const needYocto = BigInt(Math.ceil(wasm.length / 100_000 * 1e6)) * BigInt(1e18) + BigInt(15) * BigInt(1e23);
  if (!exists) {
    await owner.createAccount(contractId, deployKey.getPublicKey(), needYocto);
    console.log(`created ${contractId} with ${Number(needYocto / BigInt(1e21)) / 1000} NEAR`);
  } else {
    const keys = await contract.getAccessKeys();
    if (!keys.some((k: any) => k.public_key === deployKey.getPublicKey().toString()))
      throw new Error(`${contractId} exists and the saved deploy key is not on it; pick another GUARDRAIL_ACCOUNT`);
    const bal = BigInt((await contract.state()).amount);
    if (bal < needYocto) {
      await owner.sendMoney(contractId, needYocto - bal);
      console.log(`topped up ${contractId} by ${Number((needYocto - bal) / BigInt(1e21)) / 1000} NEAR`);
    }
  }

  // 2. deploy + init
  await contract.deployContract(wasm);
  await contract.functionCall({ contractId, methodName: "new", args: { owner: owner.accountId, mpc: cfg.mpc, policy }, gas: GAS_50 });
  console.log("deployed and initialised; mpc =", cfg.mpc);

  // 3. agent function-call key (registered by the contract in the AddKey callback)
  const agentKey = KeyPair.fromRandom("ed25519");
  const r = await call<boolean>(owner, "add_agent_key", { public_key: agentKey.getPublicKey().toString() }, GAS_50);
  if (r.result !== true) throw new Error("add_agent_key did not register the key");
  const keyFile = join(AGENT_DIR, ".agent-key.json");
  writeFileSync(keyFile, JSON.stringify({ account_id: contractId, public_key: agentKey.getPublicKey().toString(), private_key: agentKey.toString() }, null, 2), { mode: 0o600 });
  console.log("agent key added, saved to", keyFile);

  // 4. remove the deploy key so only owner + agent FC keys remain
  if (!process.argv.includes("--keep-fa-key")) {
    await call(owner, "delete_account_key", { public_key: deployKey.getPublicKey().toString() }, GAS_50);
    unlinkSync(deployKeyFile);
    console.log("deploy full-access key deleted (and its local file)");
  }
  const keys = await contract.getAccessKeys();
  console.log("access keys now:", keys.map((k: any) => `${k.public_key} ${JSON.stringify(k.access_key.permission)}`).join("\n  "));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
