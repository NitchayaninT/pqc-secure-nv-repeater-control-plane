# Instruction List
## Application (high level)
- GET_EPR_PAIR() : 
- SEND_EPR_PAIR() : generates epr pair between A and B
## Control Plane Control Messages
### 1. Post Quantum Cryptographic Handshake Establishment
Purpose : To achieve a secure classical channel session between 2 parties that is impossible for future quantum computer to break. Prevent attacks from Harvest Now, Decrypt Later (HNDL), Shor algorithm brute force
- **PQC_SYN** : request to initiate connection
- **PQC_ACK** : receiver acknowledges the request and lets the sender know
- **PQC_READY** : both of the nodes are ready to perform pqc steps
- **PQC_SEND_PK** : receiver performs keygen and send pk to sender
- **PQC_SEND_CT** : then sender encapsulate pk to get ct and shared secret 1, and send ct to receiver
- **PQC_DONE** : receiver receives ct and decapsulate it to get another shared secret (shared secret = session key)
- **HKDF_DONE** : combine shared secret with a salt to hash in order to get **encryption key** for classical messages
## 2. Entanglement Generation 
- CAL_PATH
- CAL_PATH_ACK
- ENT_ATTEMPT
- ENT_SUCCESS / ENT_FAIL
- ENT_STANDARDIZE_CHECK
- ENT_STANDARDIZE_TRUE
- ENT_STANDARDIZE_FALSE
- 