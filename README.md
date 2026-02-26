# Design and Evaluation of a PQC-Secure Classical Control Plane for NV-Center Quantum Repeater Nodes
The control plane coordinates entanglement generation, memory allocation, and local operations across NV-center repeater nodes using classical messaging and event-driven state machines. It accounts for probabilistic entanglement success and classical communication delays while ensuring authenticated and deterministic execution of local quantum operations.
## Problem
Although physical mechanisms of entanglement generation and storage have been widely studied, the classical coordination required to operate these nodes reliably remains underdeveloped and security assumptions are often implicit. If a classical channel is insecure, the information about the node that is trying to be entangled with others will get leaked, thus a possible eavesdropper or MITM can intercept the traffic and decrypt the information later. Without a secure and well-designed control plane, coherence loss and attacks are possible.
## Goal
Design a secure classical control plane that 
- Uses PQC (KyberKEM) for handshake establishment process in classical channel
- Coordinates entanglement generation & swapping
- Preserves coherence of NV nuclear memories
- Resists Store now, decrypt later and MITM attacks
- Evaluate trade off between security overhead & quantum performance
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
- Evaluation (Is using PQC to secure classical information worth it?)
	- PQC computational latency compared with non-PQC latency
	- Network transmission overhead using huge PQC elements and not using it
	- Impact of security overhead in entanglement generation and entanglement swapping
	- Eavesdropping test between using PQC and non-PQC
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
pip install qunetsim
```
5. You can try running our python code to test it out
```bash
python3 ./src/PQC_handshake.py
```