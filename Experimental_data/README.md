# Experimental Data

This directory primarily includes data from empirical studies on EVM Inequivalent Defects (including security audit reports and Stack Overflow posts), as well as the experimental results for the three research questions (RQs).

- `RQ1`: **_How does EquivGuard perform on real large-scale datasets?_** We used an open-source dataset of 287,267 Ethereum contract source codes from the [smart-contract-sanctuary-ethereum](https://github.com/tintinweb/smart-contract-sanctuary-ethereum/tree/015d0105102504dc8733a18c3543f87f1829a5e8/contracts/mainnet) repository, which has been authenticated by Etherscan. Including detected types of EVM Inequivalent Defects such as Cross-Chain Replay Attack (CCRA), Time Discrepancy Trap (TDT), Fixed Gas Reentrancy (FGR), Block Height Misalignment (BHM), Phishing Contract Address (PCA), and Gas limit Imbalance (GLI).

- `RQ2`: **_What is the performance of EquivGuard in detecting EVM Inequivalent Defects?_** We randomly sampled and manually analyzed false positives and false negatives from the RQ1 detection results to assess Precision and Recall. We used a confidence interval-based sampling method with a 95% confidence level and a 10 confidence interval.

- `RQ3`: **_How prevalent are EVM Inequivalent Defects in real-world smart contracts?_** We analyzed the multi-chain asset distribution and transactions of contracts containing defects. We collected and analyzed data from six mainstream blockchains (Ethereum, Binance Smart Chain, Arbitrum, Polygon, Optimism, and Avalanche) that account for 80.64% of the total market assets, using data from DefiLlama.

- `Security_audit`: Includes 1,322 open-source audit reports and 57 security analysis blogs collected from publicly available resources of 30 security teams.
- `Stackoverflow_posts`: Includes 326 relevant Stack Overflow posts filtered using tags such as "Solidity Contract", "EVM", "EVM Equivalent", and "EVM Compatible".


File Structure:

```
Experimental_data
├── README.md # Documentation for the Experimental_data folder
├── RQ1 # Detection results for the 6 types of defects at scale
│   ├── BHM.csv
│   ├── CCRA.csv
│   ├── FGR.csv
│   ├── GLI.csv
│   ├── PCA.csv
│   └── TDT.csv
├── RQ2 # Sampled analysis of the RQ1 large-scale detection results
│   ├── BHM.csv
│   ├── CCRA.csv
│   ├── FGR.csv
│   ├── GLI.csv
│   ├── PCA.csv
│   └── TDT.csv
├── RQ3 # Analysis of assets containing EVM Inequivalent Defects across different blockchains
│   ├── Address                 # Addresses containing different EVM Inequivalent Defects
│   ├── Balance(USD)            # Balances (in USD) of addresses containing different EVM Inequivalent Defects    
│   └── Token                   # Token balances of addresses containing different EVM Inequivalent Defects
├── Security_audit              # Blockchain security audit reports from different security companies
│   ├── Blocksecteam_solidity   # Blocksecteam
│   ├── DAppSCAN-main           # Dappscan: building large-scale datasets for smart contract...  (paper)
│   ├── SlowMist-open-report    # SlowMist
│   ├── Trailofbits_reviews     # Trail of bits
│   ├── Web3Bug                 # Demystifying Exploitable Bugs in Smart Contracts (paper)
│   └── security vulnerabilities reports.md
└── Stackoverflow_posts # Collected Stack Overflow posts
    ├── adaptive_stackoverflow_data.csv
    ├── corrective_stackoverflow_data.csv
    ├── perfective_stackoverflow_data.csv
    ├── preventive_stackoverflow_data.csv
    ├── stackoverflow_posts.csv
    ├── uncategorized_stackoverflow_data.csv
    ├── user_keyword_matches_adaptive.csv
    └── user_keyword_matches_corrective.csv
```
