import base64
import socket
import threading
import random
import os
import time
import hashlib
import argparse
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import utils

HOST = '127.0.0.1'
PORT = 9000
TIMESTAMP_TOLERANCE = 5

def generate_elgamal_keys():
    p, g = utils.get_prime_and_generator()
    x = random.randint(2, p - 2) 
    y = pow(g, x, p) 
    return (p, g, y), x  # Public key tuple (p, g, y) and private key x

def encrypt_session_key(msg, eoc_public_key):
    p, g, y = eoc_public_key
    if isinstance(msg, bytes):
        msg = int.from_bytes(msg, byteorder='big')
    
    # Choose a random ephemeral key. 1 and p-1 are edge cases and guessed first. So excluding them.
    k = random.randint(2, p - 2)
    
    c1 = pow(g, k, p)
    c2 = (msg * pow(y, k, p)) % p
    
    return c1, c2

def decrypt_session_key(cipher_msg, private_key, p):
    c1, c2 = cipher_msg
    s = pow(c1, private_key, p)
    s_inv = pow(s, p - 2, p)
    session_key = (c2 * s_inv) % p
    
    return session_key

def sign_data(data, private_key, public_key):
    p, g, y = public_key
    hash_value = int(hashlib.sha256(data.encode()).hexdigest(), 16) % (p-1)
    k = utils.find_coprime(p-1)   # Choose a random k that is coprime to p-1
    r = pow(g, k, p)
    k_inv = pow(k, -1, p-1)
    s = (k_inv * (hash_value - private_key * r) % (p-1)) % (p-1)
    
    return (r, s)

def verification(dataToVerify, public_key, sgndata):
    p, g, y = public_key
    sig_r, sig_s = sgndata
    
    # Check if r and s is in the valid range
    if not (1 <= sig_r < p or 1 <= sig_s < p-1):
        return False
    
    hash_value = int(hashlib.sha256(dataToVerify.encode()).hexdigest(), 16) % (p-1)
    left_side = pow(g, hash_value, p)
    right_side = (pow(y, sig_r, p) * pow(sig_r, sig_s, p)) % p
    
    return left_side == right_side

@utils.measure_time(label="AES Encryption")
def encrypt_with_aes(data, key):
    if isinstance(key, int):
        key_bytes = key.to_bytes(32, byteorder='big')
    elif isinstance(key, str):
        key_bytes = hashlib.sha256(key.encode()).digest()
    else:
        key_bytes = key
        
    if isinstance(data, str):
        data_bytes = data.encode()
    elif isinstance(data, int):
        data_bytes = str(data).encode()
    else:
        data_bytes = data
        
    iv = os.urandom(16)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    
    padded_data = pad(data_bytes, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    
    encrypted_payload = base64.b64encode(iv + encrypted_data).decode('utf-8')
    return encrypted_payload, iv

def decrypt_with_aes(encrypted_payload, key):
    try:
        if isinstance(key, int):
            key_bytes = key.to_bytes(32, byteorder='big')
        elif isinstance(key, str):
            key_bytes = hashlib.sha256(key.encode()).digest()
        else:
            key_bytes = key
            
        decoded_payload = base64.b64decode(encrypted_payload)
        
        iv = decoded_payload[:16]
        ciphertext = decoded_payload[16:]
        
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        
        decrypted_data = unpad(decrypted_padded, AES.block_size)
        return decrypted_data.decode('utf-8')
    
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

def send_private_message(socket_conn, message, responder_id, session_key):
    """Send encrypted private message to EOC using session key"""
    try:
        ts = int(time.time())
        message_with_ts = f"{ts},{responder_id},{message}"
        
        encrypted_payload, _ = encrypt_with_aes(message_with_ts, session_key)
        private_msg = f"80,{encrypted_payload},{ts},{responder_id}"
        
        socket_conn.send(private_msg.encode())
        print(f"[{utils.get_timestamp()}] Sent private message to EOC")
        return True
        
    except Exception as e:
        print(f"[{utils.get_timestamp()}] Error sending private message to EOC: {e}")
        return False

def start_chat_interface(socket_conn, responder_id, session_key, chat_active):
    """Interactive chat interface for responder"""
    print(f"\n=== Emergency Chat Interface ===")
    print("Connected to Emergency Operations Center")
    print("Type 'exit' to end chat session")
    print("Type 'help' for available commands")
    print("\n--- Start typing messages ---")
    
    try:
        while chat_active['active']:
            try:
                message = input(f"Responder-{responder_id} >> ")
                if message.lower() == 'exit':
                    chat_active['active'] = False
                    break
                elif message.lower() == 'help':
                    print("\nAvailable commands:")
                    print("- 'exit': End chat session")
                    print("- 'status': Show connection status")
                    print("- 'clear': Clear screen")
                    continue
                elif message.lower() == 'status':
                    print(f"Status: Connected to EOC, Session Key Active, Responder ID: {responder_id}")
                    continue
                elif message.lower() == 'clear':
                    os.system('cls' if os.name == 'nt' else 'clear')
                    continue
                elif message.strip():
                    success = send_private_message(socket_conn, message, responder_id, session_key)
                    if not success:
                        print("Failed to send message. Connection may be lost.")
                        break
                        
            except EOFError:
                break
            except KeyboardInterrupt:
                print("\nChat interrupted by user")
                break
                
    except Exception as e:
        print(f"Chat interface error: {e}")
    finally:
        chat_active['active'] = False
        print(f"\n=== Chat Session Ended ===\n")

def handle_eoc_messages(socket_conn, responder_id, session_key, group_key_storage, chat_active):
    """Handle incoming messages from EOC"""
    while True:
        try:
            data = socket_conn.recv(4096).decode()
            if not data:
                break
                
            parts = data.split(',')
            opcode = parts[0]
            
            if opcode == "30":  # GROUP KEY DISTRIBUTION
                try:
                    encrypted_payload = parts[1]
                    ts = int(parts[2])
                    eoc_id = parts[3]
                    
                    # Verify timestamp
                    current_time = int(time.time())
                    if abs(current_time - ts) > TIMESTAMP_TOLERANCE:
                        print(f"[{utils.get_timestamp()}] Group key timestamp too old, discarding")
                        continue
                    
                    # Decrypt group key using session key
                    decrypted_group_key = decrypt_with_aes(encrypted_payload, session_key)
                    
                    if decrypted_group_key:
                        group_key_storage['key'] = int(decrypted_group_key)
                        print(f"[{utils.get_timestamp()}] Received encrypted group key from EOC-{eoc_id}")
                    else:
                        print(f"[{utils.get_timestamp()}] Failed to decrypt group key")
                        
                except Exception as e:
                    print(f"[{utils.get_timestamp()}] Error processing group key: {e}")
            
            elif opcode == "40":  # BROADCAST MESSAGE
                try:
                    encrypted_payload = parts[1]
                    ts = int(parts[2])
                    eoc_id = parts[3]
                    
                    # Verify timestamp
                    current_time = int(time.time())
                    if abs(current_time - ts) > TIMESTAMP_TOLERANCE:
                        print(f"[{utils.get_timestamp()}] Broadcast message timestamp too old, discarding")
                        continue
                    
                    # Decrypt broadcast message using group key
                    if 'key' in group_key_storage:
                        decrypted_message = decrypt_with_aes(encrypted_payload, group_key_storage['key'])
                        
                        if decrypted_message:
                            message_parts = decrypted_message.split(',', 2)
                            message_ts = int(message_parts[0])
                            message_sender = message_parts[1]
                            actual_message = message_parts[2]
                            
                            if message_ts == ts and message_sender == eoc_id:
                                print(f"\n[{utils.get_timestamp()}] *** EMERGENCY BROADCAST from {message_sender} ***")
                                print(f"MESSAGE: {actual_message}")
                                print("*** END OF EMERGENCY BROADCAST ***")
                                if chat_active['active']:
                                    print(f"Responder-{responder_id} >> ", end="", flush=True)
                            else:
                                print(f"[{utils.get_timestamp()}] Broadcast message verification failed")
                        else:
                            print(f"[{utils.get_timestamp()}] Failed to decrypt broadcast message")
                    else:
                        print(f"[{utils.get_timestamp()}] No group key available to decrypt broadcast")
                        
                except Exception as e:
                    print(f"[{utils.get_timestamp()}] Error processing broadcast message: {e}")
            
            elif opcode == "70":  # PRIVATE MESSAGE FROM EOC
                try:
                    encrypted_payload = parts[1]
                    ts = int(parts[2])
                    eoc_id = parts[3]
                    
                    # Verify timestamp
                    current_time = int(time.time())
                    if abs(current_time - ts) > TIMESTAMP_TOLERANCE:
                        print(f"[{utils.get_timestamp()}] Private message timestamp too old, discarding")
                        continue
                    
                    # Decrypt private message using session key
                    decrypted_message = decrypt_with_aes(encrypted_payload, session_key)
                    
                    if decrypted_message:
                        message_parts = decrypted_message.split(',', 2)
                        message_ts = int(message_parts[0])
                        message_sender = message_parts[1]
                        actual_message = message_parts[2]
                        
                        if message_ts == ts and message_sender == eoc_id:
                            print(f"\nEOC-{eoc_id} >> {actual_message}")
                            if chat_active['active']:
                                print(f"Responder-{responder_id} >> ", end="", flush=True)
                        else:
                            print(f"[{utils.get_timestamp()}] Private message verification failed")
                    else:
                        print(f"[{utils.get_timestamp()}] Failed to decrypt private message")
                        
                except Exception as e:
                    print(f"[{utils.get_timestamp()}] Error processing private message: {e}")
            
            elif opcode == "60":  # DISCONNECT REQUEST
                print(f"[{utils.get_timestamp()}] EOC requested disconnect")
                break
                
        except (ConnectionResetError, ConnectionAbortedError):
            print(f"[{utils.get_timestamp()}] Connection with EOC lost")
            break
        except Exception as e:
            print(f"[{utils.get_timestamp()}] Error in EOC message handling: {e}")
            break
    
    chat_active['active'] = False

def connect_to_eoc(responder_id):
    try:
        # Generate ElGamal keys for responder
        with utils.Timer(label="El Gamal Key Generation"):
            responder_public_key, responder_private_key = generate_elgamal_keys()
        
        # Connect to EOC
        socket_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_conn.connect((HOST, PORT))
        print(f"[{utils.get_timestamp()}] Connected to Emergency Operations Center at {HOST}:{PORT}")
        
        # Receive EOC public key
        eoc_data = socket_conn.recv(4096).decode()
        p_eoc, g_eoc, y_eoc = map(int, eoc_data.split(","))
        eoc_public_key = (p_eoc, g_eoc, y_eoc)
        print(f"[{utils.get_timestamp()}] Received EOC public key")
        
        # Send responder public key and ID
        p_responder, g_responder, y_responder = responder_public_key
        responder_data = f"{p_responder},{g_responder},{y_responder},{responder_id}"
        socket_conn.send(responder_data.encode())
        print(f"[{utils.get_timestamp()}] Sent responder public key and ID")
        
        # Start authentication process
        TS_i = int(time.time())
        RN_i = random.randint(1, 2**64)
        ID_GWN = "EOC-1"  # Default EOC ID
        
        # Generate session key for this connection
        K_Di_GWN = random.randint(1, 2**128)
        print(f"[{utils.get_timestamp()}] Generated session key: {K_Di_GWN}")
        
        # Encrypt session key with EOC public key
        encrypted_key = encrypt_session_key(K_Di_GWN, eoc_public_key)
        
        # Create authentication message with signature
        data_to_sign = f"{TS_i},{RN_i},{ID_GWN},{encrypted_key[0]},{encrypted_key[1]}"
        signature = sign_data(data_to_sign, responder_private_key, responder_public_key)
        
        auth_msg = f"10,{TS_i},{RN_i},{ID_GWN},{encrypted_key[0]},{encrypted_key[1]},{signature[0]},{signature[1]}"
        socket_conn.send(auth_msg.encode())
        print(f"[{utils.get_timestamp()}] Sent authentication request to EOC")
        
        # Receive authentication response
        auth_response = socket_conn.recv(4096).decode()
        
        if auth_response == "FAILED":
            print(f"[{utils.get_timestamp()}] Authentication failed")
            return False
        
        auth_parts = auth_response.split(',')
        if auth_parts[0] == "10":
            TS_GWN = int(auth_parts[1])
            RN_GWN = int(auth_parts[2])
            received_id = int(auth_parts[3])
            re_encrypted_c1 = int(auth_parts[4])
            re_encrypted_c2 = int(auth_parts[5])
            eoc_sig_r = int(auth_parts[6])
            eoc_sig_s = int(auth_parts[7])
            
            # Verify EOC signature
            data_to_verify = f"{TS_GWN},{RN_GWN},{received_id},{re_encrypted_c1},{re_encrypted_c2}"
            eoc_signature = (eoc_sig_r, eoc_sig_s)
            
            if verification(data_to_verify, eoc_public_key, eoc_signature):
                print(f"[{utils.get_timestamp()}] EOC signature verified successfully")
                
                # Decrypt re-encrypted session key to verify
                re_encrypted_key = (re_encrypted_c1, re_encrypted_c2)
                decrypted_key = decrypt_session_key(re_encrypted_key, responder_private_key, p_responder)
                
                if decrypted_key == K_Di_GWN:
                    print(f"[{utils.get_timestamp()}] Session key verification successful")
                    
                    # Generate final session key
                    session_key_unhashed = int(hashlib.sha256(f"{K_Di_GWN},{TS_i},{TS_GWN},{RN_i},{RN_GWN},{responder_id},{ID_GWN}".encode()).hexdigest(), 16)
                    
                    # Send session key verification
                    tsi_new = int(time.time())
                    session_key_hashed = int(hashlib.sha256(f"{session_key_unhashed},{tsi_new}".encode()).hexdigest(), 16)
                    
                    verification_msg = f"20,{session_key_hashed},{tsi_new}"
                    socket_conn.send(verification_msg.encode())
                    print(f"[{utils.get_timestamp()}] Sent session key verification")
                    
                    print(f"[{utils.get_timestamp()}] *** SUCCESSFULLY CONNECTED TO EOC ***")
                    print(f"[{utils.get_timestamp()}] Authentication completed - Ready for emergency communications")
                    
                    # Start message handling and chat interface
                    group_key_storage = {}
                    chat_active = {'active': True}
                    
                    # Start thread to handle incoming messages from EOC
                    message_thread = threading.Thread(
                        target=handle_eoc_messages, 
                        args=(socket_conn, responder_id, session_key_unhashed, group_key_storage, chat_active)
                    )
                    message_thread.daemon = True
                    message_thread.start()
                    
                    # Start interactive chat interface
                    chat_thread = threading.Thread(
                        target=start_chat_interface,
                        args=(socket_conn, responder_id, session_key_unhashed, chat_active)
                    )
                    chat_thread.daemon = True
                    chat_thread.start()
                    
                    # Keep main thread alive and handle user commands
                    try:
                        while chat_active['active']:
                            time.sleep(0.1)
                    except KeyboardInterrupt:
                        print(f"\n[{utils.get_timestamp()}] Responder disconnecting...")
                        chat_active['active'] = False
                    
                    # Send disconnect message
                    try:
                        socket_conn.send("60".encode())
                    except:
                        pass
                    
                else:
                    print(f"[{utils.get_timestamp()}] Session key verification failed")
                    return False
            else:
                print(f"[{utils.get_timestamp()}] EOC signature verification failed")
                return False
        else:
            print(f"[{utils.get_timestamp()}] Invalid authentication response")
            return False
            
    except Exception as e:
        print(f"[{utils.get_timestamp()}] Error connecting to EOC: {e}")
        return False
    
    finally:
        try:
            socket_conn.close()
        except:
            pass
        print(f"[{utils.get_timestamp()}] Disconnected from EOC")

def main():
    parser = argparse.ArgumentParser(description="Emergency Response Responder")
    parser.add_argument('--id', type=int, required=True, help="Responder ID (unique identifier)")
    args = parser.parse_args()
    
    responder_id = args.id
    
    print(f"[{utils.get_timestamp()}] Starting Emergency Response Responder")
    print(f"[{utils.get_timestamp()}] Responder ID: {responder_id}")
    print(f"[{utils.get_timestamp()}] Attempting to connect to Emergency Operations Center...")
    
    try:
        success = connect_to_eoc(responder_id)
        if not success:
            print(f"[{utils.get_timestamp()}] Failed to establish secure connection with EOC")
    except KeyboardInterrupt:
        print(f"\n[{utils.get_timestamp()}] Responder shutdown by user")
    except Exception as e:
        print(f"[{utils.get_timestamp()}] Fatal error: {e}")

if __name__ == "__main__":
    main()