# EquivGuard Artifact

This repository contains the introduction of the EquivGuard Tool, Experimental Data, and Datasets.

## EquivGuard_tool

The EquivGuard_tool directory includes the source code and relevant documentation for the EquivGuard tool. It contains the following contents:

- **_README.md_**: Documentation on how to install and use EquivGuard.
- **_Source Code_**: The source code for the tool.
- **_Examples_**: Contains smart contract files.

## Experimental_data

The experimental data mainly includes RQ1, RQ2, RQ3 experimental data:

- **_RQ1_**: Includes detection results on a dataset of 287,267 contract source codes, including detected types of EVM Inequivalent Defects such as Cross-Chain Replay Attack (CCRA), Time Discrepancy Trap (TDT), Fixed Gas Reentrancy (FGR), Block Height Misalignment (BHM), Phishing Contract Address (PCA), and Gas limit Imbalance (GLI).
- **_RQ2_**: Includes sampled data from EquivGuard's large-scale detection results, manually analyzed for false positives and false negatives to assess Precision and Recall. We used a confidence interval-based sampling method with a 95% confidence level and a 10 confidence interval.
- **_RQ3_**: Contains the analysis of multi-chain asset distribution and transactions of contracts containing EVM Inequivalent Defects, along with corresponding analysis scripts. Data from six mainstream chains (Ethereum, Binance Smart Chain, Arbitrum, Polygon, Optimism, and Avalanche) was collected from DefiLlama to ensure effective analysis.
- **_Security_audit_**: Includes 1,322 open-source audit reports and 57 security analysis blogs collected from publicly available resources of 30 security teams.
- **_Stackoverflow_posts_**: Includes 326 relevant Stack Overflow posts filtered using tags such as "Solidity Contract", "EVM", "EVM Equivalent", and "EVM Compatible".

## Datasets

We used an open-source dataset from a GitHub repository [smart-contract-sanctuary-ethereum](https://github.com/tintinweb/smart-contract-sanctuary-ethereum/tree/015d0105102504dc8733a18c3543f87f1829a5e8/contracts/mainnet). This dataset comprises 287,267 contract source codes, covering most of the public contracts on Ethereum, and has been authenticated by Etherscan.