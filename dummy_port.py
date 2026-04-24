# dummy_port.py
from http.server import HTTPServer, BaseHTTPRequestHandler
import os

class DummyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Celery Worker Running')

port = int(os.environ.get('PORT', 8000))
server = HTTPServer(('0.0.0.0', port), DummyHandler)
print(f"Dummy HTTP server running on port {port}")
server.serve_forever()