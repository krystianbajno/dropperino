#!/usr/bin/env python

from io import BytesIO
import os
import ssl
import argparse
import tempfile
import signal
import atexit
from http.server import SimpleHTTPRequestHandler, HTTPServer
from urllib.parse import quote, unquote
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
import shutil
import html


CSS = """
<style>
    body {
        font-family: monospace;
        background: #121212;
        color: white;
    }
    h2 {
        color: lime;
    }
    a {
        color: lime;
    }
    a:active {
        color: green;
    }
</style>
"""

class Dropperino(SimpleHTTPRequestHandler):
    def do_GET(self):
        file_obj = self.index() or self.get(self.path)
        if file_obj:
            self._copy_file_contents(file_obj, self.wfile)
            file_obj.close()
            
    def do_POST(self):
        self.post()

    def index(self):
        path = self.translate_path(self.path)
        if os.path.isdir(path):
            if not self.path.endswith('/'):
                self.redirect_response(self.path + "/")
                return None
            return self.list_directory_response(path)
        return None

    def get(self, file):
        path = self.translate_path(self.path)
        try:
            file_obj = open(path, 'rb')
        except IOError:
            self.error_response(404, "File not found")
            return None

        self.file_download_response(path)
        return file_obj

    def post(self):
        success, message = self._process_file_upload()
        self.upload_response(success, message)

    def _process_file_upload(self):
        content_type = self.headers['content-type']
        if not content_type.startswith('multipart/form-data'):
            return (False, "Unexpected content type")

        boundary = content_type.split('=')[1].encode('utf-8')
        content_length = int(self.headers['content-length'])
        line = self.rfile.readline()
        content_length -= len(line)

        if not boundary in line:
            return (False, "Content did not begin with expected boundary.")

        line = self.rfile.readline()
        content_length -= len(line)
        filename_line = line.decode('utf-8')

        filename = filename_line.split('filename=')[1].strip().strip('"')
        filename = html.escape(filename)
        filepath = os.path.join(os.getcwd(), filename)

        while True:
            line = self.rfile.readline()
            content_length -= len(line)
            if not line.strip():
                break

        try:
            with open(filepath, 'wb') as f:
                while content_length > 0:
                    line = self.rfile.readline()
                    content_length -= len(line)
                    if boundary in line:
                        break
                    f.write(line)
        except IOError:
            return (False, f"Failed to save file {html.escape(filename)}")
        
        return (True, f"File {html.escape(filename)} uploaded successfully.")

    def _copy_file_contents(self, source, output):
        shutil.copyfileobj(source, output)

    def list_directory_response(self, path):
        try:
            list_items = os.listdir(path)
        except os.error:
            self.error_response(404, "No permission to list directory")
            return None

        display_path = html.escape(unquote(self.path))
        upload_form = """
        <form enctype="multipart/form-data" method="post">
            <input type="file" name="file">
            <input type="submit" value="Upload">
        </form>
        <hr>
        """

        list_items_str = "\n".join(
            f'<li><a href="{quote(html.escape(name))}">{html.escape(name)}/</a></li>' if os.path.isdir(os.path.join(path, name)) else f'<li><a href="{quote(html.escape(name))}">{html.escape(name)}</a></li>'
            for name in sorted(list_items)
        )

        response_html = f"""
        <!DOCTYPE html>
        <html>
            <head>
                <title>Dropperino @ {display_path}</title>
            </head>
            <body>
                <h2>Dropperino @ {display_path}</h2>
                {upload_form}
                <ul>{list_items_str}</ul>
            {CSS}
            <small><b>Powered by NSA</b></small>
            </body>
        </html>
        """

        response_bytes = response_html.encode('utf-8')
        self.basic_response(200, "text/html", len(response_bytes))

        response = BytesIO()
        response.write(response_bytes)
        response.seek(0)
        return response

    def file_download_response(self, path):
        filename = os.path.basename(path)
        file_size = os.path.getsize(path)
        content_type = self.guess_type(path)

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(file_size))
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()

    def upload_response(self, success, message):
        upload_html = f"""
        <!DOCTYPE html>
        <html>
            <head>
                <title>Upload Status</title>
            </head>
            <body>
                <h2>Upload Result</h2>
                <strong>{'Success' if success else 'Failed'}:</strong> {html.escape(message)}<br>
                <a href="{html.escape(self.headers["referer"])}">Go Back</a>
            {CSS}
            <small><b>Powered by NSA</b></small>
            </body>
        </html>
        """
        response_bytes = upload_html.encode('utf-8')
        self.basic_response(200, "text/html", len(response_bytes))
        self.wfile.write(response_bytes)

    def basic_response(self, status_code, content_type, content_length):
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(content_length))
        self.end_headers()

    def error_response(self, status_code, message):
        self.send_error(status_code, message)

    def redirect_response(self, location):
        self.send_response(301)
        self.send_header("Location", location)
        self.end_headers()

cert_file = None
key_file = None

def generate_in_memory_self_signed_cert():
    global cert_file, key_file

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PL"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Masovia"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Warsaw"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"get.rekt"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"get.rekt"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(u"get.rekt")]), critical=False)
        .sign(key, hashes.SHA256())
    )

    with tempfile.NamedTemporaryFile(delete=False) as cert_temp, \
         tempfile.NamedTemporaryFile(delete=False) as key_temp:

        private_key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_temp.write(private_key_pem)
        key_temp.flush()

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        cert_temp.write(cert_pem)
        cert_temp.flush()

        cert_file = cert_temp.name
        key_file = key_temp.name
        
        print("+ Cert:", cert_file)
        print("+ Key:", key_file)

    return cert_file, key_file

def cleanup():
    if cert_file and os.path.exists(cert_file):
        os.remove(cert_file)
    if key_file and os.path.exists(key_file):
        os.remove(key_file)
    print("Temporary certificate and key files deleted.")

def handle_sigint(signal, frame):
    print("\nShutting down the server...")
    cleanup()
    exit(0)

def run_server(handler_class=Dropperino, server_class=HTTPServer, host="0.0.0.0", port=8000, use_https=False):
    server_address = (host, port)
    httpd = server_class(server_address, handler_class)

    if use_https:
        cert_file, key_file = generate_in_memory_self_signed_cert()

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)

        httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)
        print(f"Starting HTTPS server on https://{host}:{port}")
    else:
        print(f"Starting HTTP server on http://{host}:{port}")

    httpd.serve_forever()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Run a simple HTTP/HTTPS server with file upload/download support.")
    parser.add_argument('host', nargs='?', default='0.0.0.0', help="The host address to bind to (default: 0.0.0.0)")
    parser.add_argument('port', nargs='?', default=8000, type=int, help="The port to bind to (default: 8000)")
    parser.add_argument('--ssl', action='store_true', help="Enable HTTPS with a self-signed certificate.")
    args = parser.parse_args()

    atexit.register(cleanup)
    signal.signal(signal.SIGINT, handle_sigint)

    run_server(host=args.host, port=args.port, use_https=args.ssl)
