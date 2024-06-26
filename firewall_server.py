# www.theforage.com - Telstra Cyber Task 3
# Firewall Server Handler

from http.server import BaseHTTPRequestHandler, HTTPServer

host = "localhost"
port = 8000

#########
# Handle the response here 
def block_request(self):
    print("Blocking request")
    self.send_response(403)
    self.send_header("Content-Type", "text/plain")
    self.end_headers()
    self.wfile.write(b"Request blocked by firewall rule")

def handle_request(self):
    self.send_response(200)
    self.send_header("Content-Type", "application/json")
    self.end_headers()
    self.wfile.write(b"{\"status\": \"ok\"}")
#########

class ServerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        handle_request(self)

    def do_POST(self):
        # Check for malicious Spring4Shell exploit headers
        if (self.headers.get("suffix") == "%>//" and
            self.headers.get("c1") == "Runtime" and
            self.headers.get("c2") == "<%" and
            self.headers.get("DNT") == "1" and
            self.headers.get("Content-Type") == "application/x-www-form-urlencoded"):
            block_request(self)
        else:
            handle_request(self)

if __name__ == "__main__":        
    server = HTTPServer((host, port), ServerHandler)
    print("[+] Firewall Server")
    print("[+] HTTP Web Server running on: %s:%s" % (host, port))

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

    server.server_close()
    print("[+] Server terminated. Exiting...")
    exit(0)
