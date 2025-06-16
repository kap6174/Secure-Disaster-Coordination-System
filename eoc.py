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

responder_session_keys = {}
active_responders = {}
responders_lock = threading.Lock()
chat_sessions = {}  # Format: {responder_id: {"active": bool, "messages": []}}
chat_lock = threading.Lock()

def generate_elgamal_keys():
    p, g = utils.get_prime_and_generator()
    x = random.randint(2, p - 2) 
    y = pow(g, x, p) 
    return (p, g, y), x  # Public key tuple (p, g, y) and private key x

def encrypt_session_key(msg, responder_public_key):
    p, g, y = responder_public_key
    if isinstance(msg, bytes):
        msg = int.from_bytes(msg, byteorder='big')
    
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
    k = utils.find_coprime(p-1)
    r = pow(g, k, p)
    k_inv = pow(k, -1, p-1)
    s = (k_inv * (hash_value - private_key * r) % (p-1)) % (p-1)
    
    return (r, s)

def verification(dataToVerify, public_key, sgndata):
    p, g, y = public_key
    sig_r, sig_s = sgndata
    
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

def generate_group_key(eoc_private_key):
    with responders_lock:
        if not responder_session_keys:
            return None
        
        keys_str = ""
        for responder_id, session_key in responder_session_keys.items():
            keys_str += str(session_key)
        
        keys_str += str(eoc_private_key)
        group_key = int(hashlib.sha256(keys_str.encode()).hexdigest(), 16)
        return group_key

def remove_disconnected(responders_to_remove):
    for responder_id in responders_to_remove:
        if responder_id in active_responders:
            try:
                active_responders[responder_id]["socket"].close()
            except:
                pass
            del active_responders[responder_id]
        if responder_id in responder_session_keys:
            del responder_session_keys[responder_id]
        with chat_lock:
            if responder_id in chat_sessions:
                del chat_sessions[responder_id]
        print(f"[{utils.get_timestamp()}] Removed disconnected responder {responder_id}")

def broadcast_group_key(group_key, eoc_id):
    with responders_lock:
        responders_to_remove = []
        for responder_id, responder_info in active_responders.items():
            responder_socket = responder_info["socket"]
            session_key = responder_session_keys[responder_id]
            
            try:
                encrypted_payload, _ = encrypt_with_aes(str(group_key), session_key)
                ts = int(time.time())
                message = f"30,{encrypted_payload},{ts},{eoc_id}"
                responder_socket.send(message.encode())
                print(f"[{utils.get_timestamp()}] Sent encrypted group key to responder {responder_id}")
            except Exception as e:
                print(f"[{utils.get_timestamp()}] Error sending group key to responder {responder_id}: {e}")
                responders_to_remove.append(responder_id)
        
        remove_disconnected(responders_to_remove)

def broadcast_message(message, group_key, eoc_id):
    ts = int(time.time())
    message_with_ts = f"{ts},{eoc_id},{message}"

    encrypted_payload, _ = encrypt_with_aes(message_with_ts, group_key)
    broadcast_msg = f"40,{encrypted_payload},{ts},{eoc_id}"
    
    with responders_lock:
        responders_to_remove = []
        for responder_id, responder_info in active_responders.items():
            responder_socket = responder_info["socket"]
            try:
                responder_socket.send(broadcast_msg.encode())
                print(f"[{utils.get_timestamp()}] Broadcasted encrypted message to responder {responder_id}")
            except Exception as e:
                print(f"[{utils.get_timestamp()}] Error broadcasting to responder {responder_id}: {e}")
                responders_to_remove.append(responder_id)

        remove_disconnected(responders_to_remove)

def send_private_message(responder_id, message, eoc_id):
    with responders_lock:
        if responder_id not in active_responders or responder_id not in responder_session_keys:
            print(f"[{utils.get_timestamp()}] Responder {responder_id} not found or not authenticated")
            return False
        
        responder_socket = active_responders[responder_id]["socket"]
        session_key = responder_session_keys[responder_id]
        
        try:
            ts = int(time.time())
            message_with_ts = f"{ts},{eoc_id},{message}"
            
            encrypted_payload, _ = encrypt_with_aes(message_with_ts, session_key)
            private_msg = f"70,{encrypted_payload},{ts},{eoc_id}"
            
            responder_socket.send(private_msg.encode())
            print(f"[{utils.get_timestamp()}] Sent private message to responder {responder_id}")
            
            with chat_lock:
                if responder_id not in chat_sessions:
                    chat_sessions[responder_id] = {"active": False, "messages": []}
                chat_sessions[responder_id]["messages"].append({
                    "sender": f"EOC-{eoc_id}",
                    "message": message,
                    "timestamp": ts
                })
            
            return True
            
        except Exception as e:
            print(f"[{utils.get_timestamp()}] Error sending private message to responder {responder_id}: {e}")
            return False

def start_chat_session(responder_id, eoc_id):
    with chat_lock:
        if responder_id not in chat_sessions:
            chat_sessions[responder_id] = {"active": False, "messages": []}
        
        if chat_sessions[responder_id]["active"]:
            print(f"[{utils.get_timestamp()}] Chat session with responder {responder_id} is already active")
            return
        
        chat_sessions[responder_id]["active"] = True
    
    print(f"\n=== Starting Chat Session with Responder {responder_id} ===")
    print("Type 'exit' to end chat session")
    print("Chat History:")
    
    # Display full chat history
    with chat_lock:
        if chat_sessions[responder_id]["messages"]:
            for msg in chat_sessions[responder_id]["messages"]:
                print(f"[{time.strftime('%H:%M:%S', time.localtime(msg['timestamp']))}] {msg['sender']}: {msg['message']}")
        else:
            print("No previous messages")
    
    print("\n--- Start typing messages ---")
    
    try:
        while True:
            message = input(f"EOC-{eoc_id} >> ")
            if message.lower() == 'exit':
                break
            elif message.strip():
                success = send_private_message(responder_id, message, eoc_id)
                if not success:
                    print("Failed to send message. Responder may be disconnected.")
                    break
                    
    except KeyboardInterrupt:
        print("\nChat session interrupted")
    finally:
        with chat_lock:
            if responder_id in chat_sessions:
                chat_sessions[responder_id]["active"] = False
        print(f"\n=== Ended Chat Session with Responder {responder_id} ===\n")

def disconnect_all_responders():
    with responders_lock:
        for responder_id, responder_info in active_responders.items():
            responder_socket = responder_info["socket"]
            try:
                responder_socket.send("60".encode())
                responder_socket.close()
                print(f"[{utils.get_timestamp()}] Disconnected responder {responder_id}")
            except Exception as e:
                print(f"[{utils.get_timestamp()}] Error disconnecting responder {responder_id}: {e}")
        
        active_responders.clear()
        responder_session_keys.clear()
        
    with chat_lock:
        chat_sessions.clear()

def handle_responder_message(responder_id, message, eoc_id):
    with chat_lock:
        if responder_id not in chat_sessions:
            chat_sessions[responder_id] = {"active": False, "messages": []}
        
        chat_sessions[responder_id]["messages"].append({
            "sender": f"Responder-{responder_id}",
            "message": message,
            "timestamp": int(time.time())
        })
        
        # Check if any chat session is active
        active_chat = None
        for rid, session in chat_sessions.items():
            if session["active"]:
                active_chat = rid
                break
        
        # If EOC is in a chat with a different responder, show notification
        if active_chat is not None and active_chat != responder_id:
            print(f"\n[{utils.get_timestamp()}] Responder {responder_id} is trying to connect")
            print(f"EOC-{eoc_id} >> ", end="", flush=True)
        # If no active chat, show notification
        elif active_chat is None:
            print(f"\n[{utils.get_timestamp()}] Responder {responder_id} is trying to connect")
        # If chatting with this responder, display the message
        elif active_chat == responder_id:
            print(f"\nResponder-{responder_id} >> {message}")
            print(f"EOC-{eoc_id} >> ", end="", flush=True)

def handle_responder(responder_socket, addr, eoc_public_key, eoc_private_key, eoc_id):
    responder_id = None
    responder_public_key = None
    
    try:
        print(f"[{utils.get_timestamp()}] Connected to responder at {addr}")
        
        p_eoc, g_eoc, y_eoc = eoc_public_key
        responder_socket.send(f"{p_eoc},{g_eoc},{y_eoc}".encode())
        
        responder_data = responder_socket.recv(4096).decode()
        p_responder, g_responder, y_responder, responder_id = map(int, responder_data.split(","))
        responder_public_key = (p_responder, g_responder, y_responder)
         
        auth_req = responder_socket.recv(4096).decode()
        auth_split = auth_req.split(',')
        opcode = auth_split[0]

        if(opcode == "10"): 
            TS_i = int(auth_split[1])
            RN_i = int(auth_split[2])
            ID_GWN = auth_split[3]
            enc_key_c1 = int(auth_split[4])
            enc_key_c2 = int(auth_split[5])
            sig_r = int(auth_split[6])
            sig_s = int(auth_split[7])

            if(ID_GWN != eoc_id):
                print(f"Fake responder. Expected id: {eoc_id}, Got {ID_GWN}")
                responder_socket.send("FAILED".encode())
                return
            
            current_time = int(time.time())
            if abs(current_time - TS_i) > TIMESTAMP_TOLERANCE:  
                print(f"[{utils.get_timestamp()}] Timestamp verification failed")
                responder_socket.send("FAILED".encode())
                return
                
            signature = (sig_r, sig_s) 
            data_to_verify = f"{TS_i},{RN_i},{ID_GWN},{enc_key_c1},{enc_key_c2}"

            if verification(data_to_verify, responder_public_key, signature):
                print(f"[{utils.get_timestamp()}] Responder {responder_id} authenticated successfully")
            else:
                print(f"[{utils.get_timestamp()}] Bad responder - Signature verification failed")
                responder_socket.send("FAILED".encode())
                return
            
            encrypted_key = (enc_key_c1, enc_key_c2)
            K_Di_GWN = decrypt_session_key(encrypted_key, eoc_private_key, p_eoc)
            print(f"[{utils.get_timestamp()}] Decrypted session key from responder: {K_Di_GWN}")

            TS_GWN = int(time.time())
            RN_GWN = random.randint(1, 2**64)
            id = responder_id  

            re_encrypted_key = encrypt_session_key(K_Di_GWN, responder_public_key)

            data_to_sign = f"{TS_GWN},{RN_GWN},{id},{re_encrypted_key[0]},{re_encrypted_key[1]}"
            eoc_signature = sign_data(data_to_sign, eoc_private_key, eoc_public_key)
            
            response = f"10,{TS_GWN},{RN_GWN},{id},{re_encrypted_key[0]},{re_encrypted_key[1]},{eoc_signature[0]},{eoc_signature[1]}"
            responder_socket.send(response.encode())
            print(f"[{utils.get_timestamp()}] Sent authentication response to responder {responder_id}")
            print("OPCODE 10 : KEY_VERIFICATION (SUCCESS)")
            
            verification_msg = responder_socket.recv(4096).decode()
            verification_parts = verification_msg.split(',')

            if verification_parts[0] == "20":
                session_key_recv = int(verification_parts[1])
                tsi_new = int(verification_parts[2])

                current_time = int(time.time())
                if abs(current_time - tsi_new) > 5:
                    print(f"[{utils.get_timestamp()}] Timestamp verification failed for session key verification")
                    return

                session_key_unhashed = int(hashlib.sha256(f"{K_Di_GWN},{TS_i},{TS_GWN},{RN_i},{RN_GWN},{responder_id},{eoc_id}".encode()).hexdigest(), 16)
                session_key_hashed = int(hashlib.sha256(f"{session_key_unhashed},{tsi_new}".encode()).hexdigest(), 16)  

                if session_key_hashed == session_key_recv:
                    print(f"[{utils.get_timestamp()}] Session key verification successful for responder {responder_id}")
                    print("OPCODE 20 : SESSION_TOKEN")
                    
                    with responders_lock:
                        responder_session_keys[responder_id] = session_key_unhashed
                        active_responders[responder_id] = {
                            "socket": responder_socket, 
                            "public_key": responder_public_key,
                            "addr": addr
                        }
                        
                    print(f"[{utils.get_timestamp()}] Responder {responder_id} added to the system")
                else:
                    print(f"[{utils.get_timestamp()}] Bad Responder {responder_id} -- session key not matched")
                    return
            else:
                print(f"[{utils.get_timestamp()}] Invalid Opcode. Expected: 20. Got: {verification_parts[0]}")
        else:
            print(f"[{utils.get_timestamp()}] Invalid Opcode. Expected: 10. Got: {opcode}")
            return
            
        while True:
            try:
                data = responder_socket.recv(4096).decode()
                if not data:
                    break
                    
                parts = data.split(',')
                opcode = parts[0]
                
                if opcode == "60":
                    print(f"[{utils.get_timestamp()}] Responder {responder_id} requested disconnect")
                    break
                elif opcode == "80":
                    try:
                        encrypted_payload = parts[1]
                        ts = int(parts[2])
                        sender_id = parts[3]
                        
                        current_time = int(time.time())
                        if abs(current_time - ts) > 5:
                            print(f"[{utils.get_timestamp()}] Message timestamp too old, discarding")
                            continue
                        
                        session_key = responder_session_keys[responder_id]
                        decrypted_data = decrypt_with_aes(encrypted_payload, session_key)
                        
                        if decrypted_data:
                            message_parts = decrypted_data.split(',', 2)
                            message_ts = int(message_parts[0])
                            message_sender = message_parts[1]
                            actual_message = message_parts[2]
                            
                            if message_ts == ts and message_sender == sender_id:
                                handle_responder_message(responder_id, actual_message, eoc_id)
                            else:
                                print(f"[{utils.get_timestamp()}] Message verification failed")
                        else:
                            print(f"[{utils.get_timestamp()}] Failed to decrypt message from responder {responder_id}")
                            
                    except Exception as e:
                        print(f"[{utils.get_timestamp()}] Error processing private message: {e}")
                
            except (ConnectionResetError, ConnectionAbortedError):
                print(f"[{utils.get_timestamp()}] Connection with responder {responder_id} lost")
                break
            except Exception as e:
                print(f"[{utils.get_timestamp()}] Error in responder {responder_id} communication: {e}")
                break
                
    except Exception as e:
        print(f"[{utils.get_timestamp()}] Error handling responder at {addr}: {e}")
    
    finally:
        if responder_id:
            with responders_lock:
                if responder_id in active_responders:
                    del active_responders[responder_id]
                if responder_id in responder_session_keys:
                    del responder_session_keys[responder_id]
            
            with chat_lock:
                if responder_id in chat_sessions:
                    chat_sessions[responder_id]["active"] = False
                    
        try:
            responder_socket.close()
        except:
            pass
            
        print(f"[{utils.get_timestamp()}] Connection with responder {responder_id if responder_id else addr} closed")

def start_eoc_server(eoc_id):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"[{utils.get_timestamp()}] Emergency Operations Center started at {HOST}:{PORT}")

    with utils.Timer(label="El Gamal Key Generation"):
        eoc_public_key, eoc_private_key = generate_elgamal_keys()
        
    eoc_thread = threading.Thread(target=eoc_command_handler, args=(eoc_public_key, eoc_private_key, eoc_id))
    eoc_thread.daemon = True 
    eoc_thread.start()

    try:
        while True:
            responder_socket, addr = server_socket.accept()
            threading.Thread(
                target=handle_responder, 
                args=(responder_socket, addr, eoc_public_key, eoc_private_key, eoc_id)
            ).start()
    except KeyboardInterrupt:
        print(f"[{utils.get_timestamp()}] EOC shutting down...")
    finally:
        disconnect_all_responders()
        server_socket.close()

def eoc_command_handler(eoc_public_key, eoc_private_key, eoc_id):    
    while True:
        try:
            print("\n=== Emergency Operations Center Command Interface ===")
            print("1: List connected responders")
            print("2: Broadcast emergency message to all responders")
            print("3: Start private chat with responder")
            print("4: View chat history")
            print("5: Disconnect all responders")
            print("6: Exit EOC")
            command = input("\nEnter command: ")
            
            if command == "1":
                with responders_lock:
                    if not active_responders:
                        print("No responders connected")
                    else:
                        print(f"Connected responders ({len(active_responders)}):")
                        for responder_id, responder_info in active_responders.items():
                            chat_status = ""
                            with chat_lock:
                                if responder_id in chat_sessions:
                                    if chat_sessions[responder_id]["active"]:
                                        chat_status = " [CHAT ACTIVE]"
                                    elif chat_sessions[responder_id]["messages"]:
                                        chat_status = f" [{len(chat_sessions[responder_id]['messages'])} messages]"
                            print(f"- Responder ID: {responder_id} - {responder_info['addr']}{chat_status}")

            elif command == "2":
                message = input("Enter emergency message to broadcast: ")
                with utils.Timer("Broadcast Emergency Message"):   
                    with responders_lock:
                        if not active_responders:
                            print("No responders connected. Cannot broadcast message.")
                            continue
                    
                    group_key = generate_group_key(eoc_private_key)
                    if not group_key:
                        print("Failed to generate group key for broadcast")
                        continue
                    
                    broadcast_group_key(group_key, eoc_id)
                    broadcast_message(message, group_key, eoc_id)
                    print("OPCODE 40 : ENC_MSG")
                    print(f"Emergency message broadcasted to {len(active_responders)} responders")
                    
            elif command == "3":
                with responders_lock:
                    if not active_responders:
                        print("No responders connected")
                        continue
                    
                    print("Available responders:")
                    for responder_id in active_responders:
                        chat_status = ""
                        with chat_lock:
                            if responder_id in chat_sessions and chat_sessions[responder_id]["active"]:
                                chat_status = " [CHAT ACTIVE]"
                        print(f"- {responder_id}{chat_status}")
                
                try:
                    responder_id = int(input("Enter responder ID to chat with: "))
                    if responder_id in active_responders:
                        # Check if another chat is active
                        chat_active = False
                        with chat_lock:
                            for rid, session in chat_sessions.items():
                                if session["active"] and rid != responder_id:
                                    print(f"Warning: Chat with responder {rid} is currently active.")
                                    continue_chat = input("Do you want to start a new chat anyway? (y/n): ")
                                    if continue_chat.lower() != 'y':
                                        chat_active = True
                                        break
                        
                        if not chat_active:
                            start_chat_session(responder_id, eoc_id)
                    else:
                        print("Responder not found")
                except ValueError:
                    print("Invalid responder ID")
                    
            elif command == "4":
                with chat_lock:
                    if not chat_sessions:
                        print("No chat history available")
                        continue
                    
                    print("Responders with chat history:")
                    for responder_id, session in chat_sessions.items():
                        status = "ACTIVE" if session["active"] else "INACTIVE"
                        print(f"- Responder {responder_id}: {len(session['messages'])} messages [{status}]")
                    
                    try:
                        responder_id = int(input("Enter responder ID to view history (0 for all): "))
                        if responder_id == 0:
                            for rid, session in chat_sessions.items():
                                print(f"\n=== Chat History with Responder {rid} ===")
                                for msg in session["messages"]:
                                    print(f"[{time.strftime('%H:%M:%S', time.localtime(msg['timestamp']))}] {msg['sender']}: {msg['message']}")
                        elif responder_id in chat_sessions:
                            print(f"\n=== Chat History with Responder {responder_id} ===")
                            for msg in chat_sessions[responder_id]["messages"]:
                                print(f"[{time.strftime('%H:%M:%S', time.localtime(msg['timestamp']))}] {msg['sender']}: {msg['message']}")
                        else:
                            print("No chat history found for this responder")
                    except ValueError:
                        print("Invalid responder ID")
            
            elif command == "5":  
                disconnect_all_responders()
                print("All responders disconnected")
            
            elif command == "6":  
                print("Shutting down Emergency Operations Center...")
                disconnect_all_responders()
                os._exit(0) 
            
            else:
                print("Invalid command")
                
        except Exception as e:
            print(f"Error processing command: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Emergency Operations Center (EOC)")
    parser.add_argument('--id', type=str, default="EOC-1", help="EOC identifier")
    args = parser.parse_args()

    eoc_id = args.id

    start_eoc_server(eoc_id)