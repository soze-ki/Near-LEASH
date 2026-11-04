/** Print the guardrail's derived EVM address for a path, so the human can fund it. */
import { derivedAddress, provider } from "./evm.js";
import { formatEther } from "ethers";

const path = process.argv[2] ?? "treasury-base";
const a = await derivedAddress(path);
const bal = await provider().getBalance(a);
console.log(`${path}: ${a}  balance ${formatEther(bal)} ETH`);
