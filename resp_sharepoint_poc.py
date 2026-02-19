from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import json

class SharePointMimic(BaseHTTPRequestHandler):
    # Common SharePoint headers used for both GET and POST
    def _set_sp_headers(self, status=200, content_type="text/html"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("MicrosoftSharePointTeamServices", "16.0.0.10337")
        self.send_header("X-SharePointHealthScore", "0")
        self.send_header("SPRequestGuid", "5bc6929f-e0d0-0000-269a-669d06859389")
        self.send_header("Server", "Microsoft-IIS/10.0")
        self.end_headers()

    def do_GET(self):
        # Route: SOAP/Web Service Endpoints (High confidence indicators)
        if "/_vti_bin/" in self.path:
            self._set_sp_headers(200, "text/xml")
            xml_response = '<?xml version="1.0" encoding="utf-8"?><definitions xmlns:s="http://www.w3.org"> SharePoint Service </definitions>'
            self.wfile.write(xml_response.encode())
            
        # Route: System Layouts (Where scanners check for vulnerabilities)
        elif "/_layouts/15/" in self.path:
            self._set_sp_headers(200)
            self.wfile.write(b"<html><body>Access Denied - SharePoint System Page</body></html>")

        # Route: Default Landing Page
        else:
            self._set_sp_headers(200)
            self.wfile.write(b'<html><head><meta name="GENERATOR" content="Microsoft SharePoint" /></head><body>SharePoint Home</body></html>')

    def do_POST(self):
        # This is where scanners try to exploit services or upload shells
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')

        print(f"[!] POST received on {self.path} from {self.address_string()}")
        
        # TRIGGER YOUR SPECIFIC FUNCTIONS HERE
        if "/_vti_bin/Lists.asmx" in self.path:
            self.handle_list_service_exploit(post_data)
        elif "CustomEndpoint" in self.path:
            self.your_custom_logic_function(post_data)

        # Return a generic XML SOAP fault or success to keep the scanner interested
        self._set_sp_headers(200, "text/xml")
        self.wfile.write(b'<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org"><soap:Body><Response>Success</Response></soap:Body></soap:Envelope>')

    def handle_list_service_exploit(self, data):
        print(f"[*] Analyzing SOAP Payload: {data[:100]}...")
        # Add your analysis or logging logic here

    def your_custom_logic_function(self, data):
        # Insert your specific set of functions here
        pass

def run_server():
    # Use 443; requires sudo/Admin. Ensure cert.pem/key.pem exist.
    server_address = ('', 443)
    httpd = HTTPServer(server_address, SharePointMimic)
    
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        print("SharePoint Mimic Live on 443 (HTTPS)")
        httpd.serve_forever()
    except Exception as e:
        print(f"Server Error: {e}")

if __name__ == "__main__":
    run_server()