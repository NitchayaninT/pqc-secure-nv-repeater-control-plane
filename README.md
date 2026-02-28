# Design of a Secure and Deterministic Classical Control Plane for NV-Center Quantum Repeater Nodes
The control plane coordinates entanglement generation, memory allocation, and local operations across NV-center repeater nodes using classical messaging and event-driven state machines. It  accounts for probabilistic entanglement success and classical communication delays while ensuring authenticated and deterministic execution of local quantum operations.
## Problem
Although physical mechanisms of entanglement generation and storage have been widely studied, the classical coordination required to operate these nodes reliably remains underdeveloped and security assumptions are often implicit. Without a well-designed control plane, coherence loss and attacks are possible
## Goal
Design a **secure classical control plane** that coordinates entanglement generation & swapping, resists MITM attacks, future quantum computer attacks (Shor's algorithm, Harvest now, decrypt later) that can break RSA/ECC public key and evaluate trade off between security overhead & quantum performance
## PQC + QKD Integration
QKD is an application that _uses_ entanglement to secure communication (after entanglement establishment)
- PQC is required everywhere RSA/ECC are currently used, its used for securing an internal handshake of a connection (authentication)
- QKD is only feasible on fiber links, in which it can provide an additional layer of protection against long-term Harvest now decrypt later adversaries by **making the encryption keys "information-theoretically secure"**
- QKD requires a pre-established authenticated classical channel to prevent man in the middle attacks but traditional authentication (RSA/ECC) is vulnerable to quantum attacks
- PQC is used to authenticate the QKD session
- **Best use cases** : critical infrastructure such as governmental backbones, financial data centers, telecom core networks, healthcare centers

**Workflow**
1. Use PQC to authenticate the two nodes (Classical channel), to sign their classical messages
2. Use QKD to generate a shared secret (Physical channel, fiber)
3. Use QKD key to encrypt the actual data

**Reasons**
1. Protection against Harvest now, decrypt layer (HNDL)
	- There is a risk from an attacker collecting and storing data today and decrypting it at some point in the future, which is a threat for organizations that collect high-value information
2. Protection against Man in the middle (MITM) attacks. If the middleman doesn't have the correct certificate, they cannot intercept or modify the messages
3. PQC is used to make sure we are talking to the right person, verify the node**s before QKD start** (integrity)
4. QKD is used to keep a secret (confidentiality)
## Methodology
- Control plane architecture design
	- Layered control-plane stack
	- Deterministic scheduling policies
- NV-center behavior abstraction model
	- Model probabilistic entanglement attempts
	- Local operation latencies (swap, measure, correction)
- Protocol implementation in QuNetSim
	- Control plane logic
	- Node level orchestration
	- Secure classical messaging using PQC
	- Timeout handling
- Evaluation
	- Control-plane latency
	- Entanglement success probability under scheduling strategies
	- Coherence-time consumption
	- Impact of security overhead (authentication, handshake)
## Software Used : QuNetSim
Why QuNetSim?
QuNetSim is a high-level quantum network simulator designed for developing and testing quantum networking applications and protocols at the network and application layers. It enables rapid prototyping of control and communication protocols without requiring detailed physical-layer modeling. This makes QuNetSim well-suited for this project, which focuses on the design of a post-quantum secure classical control plane and its performance evaluation.
## How to run QuNetSim in your device?
1. Follow the instructions on the official website first
https://tqsd.github.io/QuNetSim/install.html

2. However, QuNetSim has not been updated to use newer versions of matplotlib, scapy and numpy. Make sure to downgrade them before installing QuNetSim
Recommended versions :
- matplotlib==3.5.3
- numpy==1.22.4
- scipy==1.9.3

Downgrade after installing a virtual environment
```bash
pip install matplotlib==3.5.3 numpy==1.22.4 scipy==1.9.3
```
3. Install QuNetSim
```bash
pip install QuNetSim
```
4. Once you log out and log back in, you have to reactivate a virtual environment and reinstall qunetsim
```bash
source .venv/bin/activate
pip install QuNetSim
```