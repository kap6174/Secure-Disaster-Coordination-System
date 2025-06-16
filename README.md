# SafeLink – Secure Disaster Response Coordination System

## Overview
This project implements a secure communication platform for natural disaster response, enabling first responders (e.g., paramedics, firefighters) and an Emergency Operations Center (EOC) to coordinate securely in high-pressure environments. The system ensures **confidentiality**, **integrity**, and **authentication** through cryptographic protocols: **ElGamal** for asymmetric key exchange and digital signatures, **AES-256** for symmetric encryption, and **SHA-256** for hashing. It supports mutual authentication, private messaging, and group broadcasting, addressing critical security needs during disaster response.

The platform is implemented in Python using `socket` for network communication and `Cryptodome` for cryptographic operations, with multithreading to handle multiple responders concurrently.

## Security Properties
The system achieves the following security properties using a combination of asymmetric and symmetric cryptography, along with digital signatures:
- **Confidentiality**:
  - **Asymmetric Cryptography**: ElGamal encrypts session keys during authentication, ensuring only intended recipients (EOC or responder) can access them.
  - **Symmetric Cryptography**: AES-256 encrypts private messages and group broadcasts, protecting sensitive data (e.g., survivor medical records) from eavesdropping.
- **Integrity**:
  - **Digital Signatures**: ElGamal-based signatures verify the authenticity of authentication requests and responses, preventing tampering with messages or keys.
  - **Hashing**: SHA-256 hashing provides integrity as well as derives secure session and group keys from multiple inputs, ensuring cryptographically strong, unique keys. Its collision resistance prevents key forgery, enhancing authentication and encryption security.
- **Authentication**:
  - **Asymmetric Cryptography and Signatures**: ElGamal key pairs and signatures enable mutual authentication between the EOC and responders, confirming their identities.
  - **Timestamps**: Messages include timestamps (verified within 5 seconds) to prevent replay attacks, ensuring communication freshness.

## System Architecture
The system comprises two components:
- **Emergency Operations Center (EOC)** (`eoc.py`): The central node that authenticates responders, manages private messaging, and broadcasts updates. It listens on `localhost:9000` and handles multiple connections via threads.
- **Responders** (`responder.py`): Devices representing first responders, each identified by a unique ID (e.g., 1001). They authenticate with the EOC, send private messages, and receive broadcasts.

### Cryptographic Workflow
1. **Initialization**:
   - The EOC and each responder generate ElGamal key pairs by selecting a large prime number, a generator, a random private key, and computing a corresponding public key.
2. **Authentication**:
   - A responder sends an authentication request to the EOC, containing a timestamp, a random number, a session key encrypted with the EOC’s public key, and a digital signature.
   - The EOC verifies the timestamp (within 5 seconds), checks the signature, and decrypts the session key using its private key.
   - The EOC responds with its timestamp, a random number, the re-encrypted session key, and its signature.
   - The responder verifies the response, confirms the session key, and both parties compute a final session key by hashing the session key, timestamps, random numbers, and their IDs.
   - The responder sends a hashed verification token, which the EOC validates to complete authentication.
3. **Group Broadcasting**:
   - The EOC generates a group key by hashing all responders’ session keys and its private key.
   - The group key is encrypted with each responder’s session key and distributed.
   - Broadcast messages are encrypted with the group key, allowing all responders to decrypt them.
4. **Private Messaging**:
   - Messages between the EOC and a responder are encrypted with their shared session key, including a timestamp and sender ID for verification.
   - Messages are stored in a chat history for later review.

## Functionalities
- **Authentication**:
  - Verifies the identities of the EOC and responders using ElGamal signatures and timestamps.
  - Establishes a unique session key for each responder, enabling secure subsequent communication.
  - Prevents unauthorized access by rejecting invalid signatures or outdated timestamps.
- **Private Messaging**:
  - Enables confidential communication between the EOC and a responder, initiated through the EOC’s command interface.
  - Encrypts messages with AES-256 using the session key, ensuring privacy.
  - Stores chat history with timestamps and sender IDs, displayed before new sessions.
  - Notifies the EOC of incoming messages from other responders during an active chat, preserving session focus.
  - Terminates sessions when either party types `exit`.
- **Group Broadcasting**:
  - Allows the EOC to send encrypted updates (e.g., evacuation zones) to all authenticated responders.
  - Uses a group key derived from session keys to encrypt broadcasts, ensuring only authorized responders can access them.
  - Supports real-time dissemination of critical information.

## Why Secure Communication Matters
Secure communication in disaster response is critical to:
- **Protect Sensitive Data**: Prevent unauthorized access to survivor locations, medical records, or resource details.
- **Ensure Integrity**: Verify that instructions (e.g., evacuation routes) are authentic and untampered.
- **Counter Cyber Threats**: Mitigate eavesdropping, replay attacks, and data manipulation during crises.
- **Enable Trust**: Foster cooperation by ensuring data privacy for responders and victims.
- **Corporate Applications**: Apply principles of secure communication to enterprise contexts, such as IoT systems or internal data protection.

## Requirements
To run the system locally, install the following:
- Python 3.9+
- Libraries:
  - `pycryptodome` (for AES and cryptographic operations)
  - `cryptography` (for Diffie-Hellman parameters in `utils.py`)

Install dependencies:
```bash
pip install pycryptodome cryptography
```

## Execution Steps
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/kap6174/Secure-Disaster-Coordination-System
   cd Secure-Disaster-Coordination-System
   ```
2. **Set Up Virtual Environment**:
   - Create and activate a virtual environment:
     ```bash
     source venv/bin/activate
     ```
3. **Run the EOC**:
   - Start the Emergency Operations Center with an ID (default: `EOC-1`):
     ```bash
     python eoc.py
     python eoc.py --id EOC-1
     ```
   - The EOC listens on `localhost:9000`.
4. **Run Responders**:
   - Start responders with unique IDs (e.g., 1001, 1002) in separate terminals (ensure the virtual environment is activated in each terminal):
     ```bash
     python responder.py --id 1001
     python responder.py --id 1002
     ```
   - Responders connect to the EOC, authenticate, and enter the messaging interface.
5. **Interact with the System**:
   - **EOC Interface**:
     - Command `1`: List connected responders.
     - Command `2`: Broadcast an emergency message.
     - Command `3`: Start a private chat with a responder, viewing chat history.
     - Command `4`: View chat history for a responder or all.
     - Command `5`: Disconnect all responders.
     - Command `6`: Shut down the EOC.
   - **Responder Interface**:
     - Send private messages to the EOC (encrypted with the session key).
     - Receive private messages or broadcasts from the EOC.
     - Use commands: `help` (list commands), `status` (connection status), `clear` (clear screen), `exit` (end chat).


## Future Improvements
- **Scalability**: Add load balancing for larger responder networks.
- **Persistent Storage**: Store chat history in a secure database.
- **Threat Detection**: Implement intrusion detection for anomalous behavior.
- **User Interface**: Develop a GUI for field usability.
- **Optimization**: Use faster cryptographic libraries (e.g., OpenSSL) for efficiency.

## Conclusion
This project provides a secure communication platform for natural disaster response, achieving confidentiality, integrity, and authentication through ElGamal, AES-256, and SHA-256. With functionalities for authentication, private messaging, and group broadcasting, it ensures reliable coordination in emergencies. The system demonstrates cryptographic protocol implementation and secure network communication, applicable to real-world and enterprise security challenges.

Project by: Junaid Ahmed M.Tech CSE, IIIT Hyderabad
