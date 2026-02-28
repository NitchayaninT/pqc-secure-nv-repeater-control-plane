# Control Plane Design

![Control Plane Architecture](Control%20Plane%20Architecture.jpeg)
Service : Entanglement Service 
	- Entanglement Generation
	- Entanglement Swapping
## Layers
- **Distributed Control Layer** : Coordinates nodes over classical links
- **Node Orchestration Layer** : NV-center node's logic. Handles deterministic execution inside a node. To safely execute instructions that distributed control decides
## Control Plane Services
### Distributed Control
1. Computes paths
2. Post-Quantum Cryptographic Handshake Establishment
3. Link-level Entanglement Generation
4. Multi-hop level Entanglement Generation (Swapping)
5. Processes measurement results
6. Decides what correction is required
7. Memory Resource Coordination
### Node Orchestration
1. Check memory availability
2. Check electron availability
3. Schedules the operations
4. Sends the instruction to Instruction interface (decoder)
5. Update memory state
### Instruction Interface Layer
1. I (Idle) : 000
2. X (Bit flip) : 001
3. Y (Bit & Phase Flip) : 010
4. Z (Phase flip) : 011
5. CNOT : 100
6. MEASURE : 101
## Table of Contents
- [Instruction List](Instuction%20List.md)
- [Quantum Network Architecture](Quantum%20Network%20Architecture.md)
- Quantum Network Stack
- [Entanglement Services](Entanglement%20Services.md)
	- Entanglement Generation
	- Entanglement Swapping