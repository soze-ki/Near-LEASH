# X post draft (the human edits and posts it)

Attach to post 1 (up to 4 images): docs/screenshots/compromised.png, tail.png, deploy.png, injected.png.
Replace REPO_LINK with the public repo URL once the repo is public. Links count as 23 characters on X.

## Post 1 (attach the video or compromised.png) — 275/280

Give an AI agent a wallet, and one scam email can make it pay a stranger.

Guardrail stops that on-chain. We stole the agent's key and attacked: every payment outside the owner's rules was refused.

Built at NEAR HACKATHON @NEARProtocol #NEARHackathon
REPO_LINK

## Reply 1: NEAR's role — 275/280

How NEAR makes it work: the agent holds a NEAR key that can only call two "please pay" methods. The money sits with a NEAR contract that controls a Base wallet through Chain Signatures, so there is no wallet private key to leak. The contract checks every payment, then signs.

## Reply 2: next step — 161/280

Code, tests and the live testnet contract are in the repo. What rule would you need before letting an agent spend your company's money? @NearBuilders @NearLegion

## Reply 3: let people check it — 150/280

Check it yourself on testnet, every denial is on-chain:
Contract: https://testnet.nearblocks.io/address/guardrail2.shortisland3107.testnet
A payment it signed on Base Sepolia: https://sepolia.basescan.org/tx/0x6cbac0ca98bc817f9eceb26d88a2a2ef7ee8edde858fc455c2b994d3a1f3e2d5
