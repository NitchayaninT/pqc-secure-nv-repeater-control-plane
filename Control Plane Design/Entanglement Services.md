# Entanglement Services
1. Entanglement Generation
2. Entanglement Swapping
## Entanglement Generation Workflow
1. The end node initiates entanglement request to adjacent node (Application)
2. Initializes NV electron spin and register to original state (0)
3. Creates spin-photon entanglement  (Entanglement attempt), now electron is entangled with **its emitted photon**
4. Exchange photons between adjacent repeater nodes (Physical)
5. Measure **heralds entanglement** using **bell-state measurement** after entanglement attempts and send result back to the node of origin (Don't send MEASURE instruction to the repeater, cuz the measurement happens on the photons at the middle station, not on the NV electron spins. Middle station (heralding station) = usually a beam splitter or detectors without any memory. Its only used to perform Bell-state measurement, so its a "measurement station", not a repeater node). It doesn't measure the electrons directly, but they're entangled through photon measurement (projection)
6. After heralding, electrons may be projected into one of the four bell states
7. But for higher-level protocols, protocols assume a known reference state (When we define that a certain pauli gate is a result of a successful entanglement). So, Apply pauli correction (conditional) after heralds for standardization so that the system can track bell state classically and use it later
8. Store the entanglement in quantum memories in quantum repeater once the attempt succeeds (CNOT)
	- Result : Nuclear spin stores entanglement (long-lived memory) and electron is free again (can entangle with another node later
	
### State Machine Diagram
### Sequence Diagram
## Entanglement Swapping Workflow
1. End to end entanglement request initiated at the end-node
2. Controller decides to perform swapping (if the end-node requests for entanglement generation with a far away node)
3. Connection request is forwarded to the receiver (repeater by repeater along the path)
4. Initializes NV electron spin and register to original state (0)
5. Receiver replies with a resource plan
6. Routers along the path generate **elementary entanglements and do swapping**
7. Repeater R performs **Bell state measurement** on its local qubits. This measurements acts as a projection, destroying the photons but entangling the distant nodes (MEASURE)
8. Heralding and Verification (measurement), End nodes are updated about end-to-end entanglement availability
9. Correction (if necessary), controller decides
10. End nodes consume end-to-end entanglement
### State Machine Diagram
### Sequence Diagram