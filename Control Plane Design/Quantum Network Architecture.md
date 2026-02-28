# Quantum Network Architecture for NV-Center Quantum Repeater Nodes with a Secure Classical Channel Session

## Application
- **Entanglement Service** 
	- Entanglement generation 
	- Entanglement swapping
## Control Plane
### 1. Distributed Control
- **Security Control**
	- PQC Secure Session Establishment
- **End-to-end Control**
	- Coordinates nodes over classical links 
	- Eg : swapping, correction (after swapping)
- **Link-layer Control**
	- Coordinates entanglement generation between 2 adjacent nodes 
	- Handles Entanglement requests (Start entanglement attempts)
	- Herald Report
	- Pauli Correction
	- TDMA schedule (Connect with centralized request scheduler)
### 2. Node Orchestration Layer (Router's logic)
- Translates classical message to **local instructions**
- Checks local state, if the nuclear register free or is the electron idle?
- Eg : START_ENTANGLEMENT(B,N2,slot=5) --> ALLOC_MEM(N2), PREPARE_ELECTRON(), SCHEDULE_ENT_ATTEMPT(slot=5), WAIT_FOR_HERALD()
- Once the link-layer control gets herald result from measurement, it sends CNOT instruction to decoder
- After that, it then sends other gate instructions to the decoder once correction is requested from an upper layer
