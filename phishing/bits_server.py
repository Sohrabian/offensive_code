from flask import Flask, send_file

app = Flask(__name__)

@app.route('/payload.exe')
def serve_payload():
    return send_file('payload.exe', as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
