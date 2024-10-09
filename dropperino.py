#!/usr/bin/env python

import os
import ssl
import signal
import shutil
import html
from io import BytesIO
from datetime import datetime, timedelta, timezone
from http.server import SimpleHTTPRequestHandler, HTTPServer
from urllib.parse import quote, unquote
from typing import Optional, Tuple

import atexit
import tempfile
import argparse

__CRYPTO_INSTALLED__ = True
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
except:
    __CRYPTO_INSTALLED__ = False

SERVER_NAME = "Dropperino"

SSL_COUNTRY_NAME = u"PL"
SSL_STATE_OR_PROVINCE_NAME = u"Masovia"
SSL_LOCALITY_NAME = u"Warsaw"
SSL_ORGANIZATION_NAME = u"get.rekt"
SSL_COMMON_NAME = u"get.rekt"

POWERED_BY = "https://github.com/krystianbajno/dropperino"

CSS = """
<style>
    body { font-family: monospace; background: #121212; color: white; }
    h2 { color: lime; }
    a { color: lime; }
    a:active { color: green; }
</style>
"""

def INDEX_VIEW(path, files):
    display_path = html.escape(unquote(path))    
    return f"""
        <!DOCTYPE html>
        <html>
            <head>
                <title>{SERVER_NAME} @ {display_path}</title>
            </head>
            <body>
                <h2>{SERVER_NAME} @ {display_path}</h2>
                
                <form enctype="multipart/form-data" method="post">
                    <input type="file" name="file">
                    <input type="submit" value="Upload">
                </form><hr>
                
                <ul>
                {"\n".join(
                    f'<li><a href="{quote(html.escape(name))}">{html.escape(name)}/</a></li>'
                    if os.path.isdir(os.path.join(path, name)) else
                    f'<li><a href="{quote(html.escape(name))}">{html.escape(name)}</a></li>'
                    for name in sorted(files)
                )}
                </ul>
                <small><b>Powered by {POWERED_BY}</b></small>
                {CSS}
            </body>
        </html>
    """
    
def UPLOAD_RESPONSE_VIEW(success, message):
    return f"""
        <!DOCTYPE html>
        <html>
            <head><title>Upload Status</title></head>
            <body>
                <h2>Upload Result</h2>
                <strong>{'Success' if success else 'Failed'}:</strong> {html.escape(message)}<br>
                <h2><a href="/">Go Back</a></h2><br>
                {CSS}
                <small><b>Powered by {POWERED_BY}</b></small>
            </body>
        </html>
    """
    

class DropperinoServer(SimpleHTTPRequestHandler):
    def __init__(self, *args, directory=None, **kwargs):
        self.base_directory = os.path.abspath(directory) if directory else os.getcwd()
        print(self.base_directory)
        super().__init__(*args, **kwargs)

    def do_GET(self):
        file_obj = self.handle_index() or self.handle_serve_file(self.path)
        if file_obj:
            self._copy_file(file_obj, self.wfile)

    def do_POST(self):
        success, message = self.handle_upload()
        self.send_html_response(UPLOAD_RESPONSE_VIEW(success, message))

    def handle_index(self) -> Optional[BytesIO]:
        path = self._translate_path(self.path)
        if os.path.isdir(path):
            if not self.path.endswith('/'):
                self.send_redirect(self.path + "/")
                return None
            return self._build_index_response(path)
        return None

    def handle_serve_file(self, file: str) -> Optional[BytesIO]:
        path = self.translate_path(self.path)
        try:
            file_obj = open(path, 'rb')
        except IOError:
            self.send_error_response(404, "File not found")
            return None

        self.send_file_headers(path)
        return file_obj

    def handle_upload(self) -> Tuple[bool, str]:
        content_type = self.headers.get('content-type', '')
        if not content_type.startswith('multipart/form-data'):
            return False, "Unexpected content type"

        boundary = content_type.split('=')[1].encode('utf-8')
        content_length = int(self.headers['content-length'])

        if not self._validate_boundary(boundary):
            return False, "Content did not begin with expected boundary."

        filename = self._extract_filename()
        filepath = os.path.join(self.base_directory, filename)

        try:
            self._save_uploaded_file(filepath, boundary, content_length)
        except IOError:
            return False, f"Failed to save file {html.escape(filename)}"
        
        return True, f"File {html.escape(filename)} uploaded successfully."
    
    def send_file_headers(self, path: str):
        file_size = os.path.getsize(path)
        content_type = self.guess_type(path)
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(file_size))
        self.send_header("Content-Disposition", f'attachment; filename="{os.path.basename(path)}"')
        self.end_headers()

    def send_html_response(self, html_content: str):
        response_bytes = html_content.encode('utf-8')
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.end_headers()
        self.wfile.write(response_bytes)

    def send_error_response(self, status_code: int, message: str):
        self.send_error(status_code, message)

    def send_redirect(self, location: str):
        self.send_response(301)
        self.send_header("Location", location)
        self.end_headers()
    
    ### -------------
    
    def _translate_path(self, path):
        path = unquote(path)
        path = path.split('?', 1)[0]
        path = path.split('#', 1)[0]
        path = os.path.normpath(path)
        return os.path.join(self.base_directory, path.lstrip('/'))

    def _validate_boundary(self, boundary: bytes) -> bool:
        line = self.rfile.readline()
        return boundary in line

    def _extract_filename(self) -> str:
        filename_line = self.rfile.readline().decode('utf-8')
        return html.escape(filename_line.split('filename=')[1].strip().strip('"'))

    def _save_uploaded_file(self, filepath: str, boundary: bytes, content_length: int):
        while True:
            line = self.rfile.readline()
            content_length -= len(line)
            if not line.strip():
                break

        with open(filepath, 'wb') as f:
            while content_length > 0:
                line = self.rfile.readline()
                content_length -= len(line)
                if boundary in line:
                    break
                f.write(line)

    def _copy_file(self, source: BytesIO, output):
        shutil.copyfileobj(source, output)

    def _build_index_response(self, path: str) -> BytesIO:
        try:
            files = os.listdir(path)
        except os.error:
            self.send_error_response(404, "No permission to list directory")
            return None

        response_html = INDEX_VIEW(path, files)
        return self.send_html_response(response_html)
        
class SSLHandler:
    def __init__(self):
        self.cert_file = None
        self.key_file = None

    def generate_self_signed_cert(self) -> Tuple[str, str]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, SSL_COUNTRY_NAME),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, SSL_STATE_OR_PROVINCE_NAME),
            x509.NameAttribute(NameOID.LOCALITY_NAME, SSL_LOCALITY_NAME),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, SSL_ORGANIZATION_NAME),
            x509.NameAttribute(NameOID.COMMON_NAME, SSL_COMMON_NAME),
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

            key_temp.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
            cert_temp.write(cert.public_bytes(serialization.Encoding.PEM))

            self.cert_file = cert_temp.name
            self.key_file = key_temp.name
            
            print("Cert:", self.cert_file)
            print("Key:", self.key_file)
            
        return self.cert_file, self.key_file


    def cleanup(self):
        if self.cert_file:
            os.remove(self.cert_file)
        if self.key_file:
            os.remove(self.key_file)
        print("Temporary certificate and key files deleted.")

    def setup_ssl_context(self, server) -> ssl.SSLContext:
        cert_file, key_file = self.generate_self_signed_cert()
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
        return ssl_context


def run_server(host: str = "0.0.0.0", port: int = 8000, use_https: bool = False, directory: str = "."):
    ssl_handler = SSLHandler()
    
    if use_https and not __CRYPTO_INSTALLED__:
        print("The 'cryptography' module is not installed. Run :: pip install cryptography. Skipping SSL.")
        use_https = __CRYPTO_INSTALLED__        
            
    server_address = (host, port)
    httpd = HTTPServer(server_address, lambda *args, **kwargs: DropperinoServer(*args, directory=directory, **kwargs))

    if use_https:
        ssl_handler.setup_ssl_context(httpd)
        print(f"Starting HTTPS server on https://{host}:{port}, serving directory: {directory}")
    else:
        print(f"Starting HTTP server on http://{host}:{port}, serving directory: {directory}")

    if use_https:
        signal.signal(signal.SIGINT, lambda sig, frame: shutdown_server(ssl_handler))
        atexit.register(ssl_handler.cleanup)

    httpd.serve_forever()

def shutdown_server(ssl_handler: SSLHandler):
    print("\nShutting down the server...")
    ssl_handler.cleanup()
    exit(0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Run an HTTP/HTTPS server with file upload/download support.")
    parser.add_argument('port', nargs='?', type=int, default=8000, help="The port to bind to (default: 8000)")    
    parser.add_argument('host', nargs='?', default='0.0.0.0', help="The host address to bind to (default: 0.0.0.0)")
    parser.add_argument('--ssl', action='store_true', help="Enable HTTPS with a self-signed certificate.")
    parser.add_argument('--dir', default=".", help="Specify the directory to serve files from (default: current directory)")

    args = parser.parse_args()

    use_https = args.ssl
    directory = os.path.abspath(args.dir)

    if not os.path.exists(directory) or not os.path.isdir(directory):
        print(f"Error: Directory '{directory}' does not exist or is not a directory.")
        exit(1)

    run_server(host=args.host, port=args.port, use_https=use_https, directory=directory)
