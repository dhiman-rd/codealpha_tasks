import http.server
import socket
import subprocess
import threading
import urllib.request


class TestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"Local Suricata IDS test\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_string, *args):
        pass


def main():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 18080), TestHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        print("Sending three ICMP echo requests to localhost...")
        subprocess.run(["ping", "-c", "3", "127.0.0.1"], check=True)

        print("Requesting the custom HTTP test URI on localhost...")
        with urllib.request.urlopen("http://127.0.0.1:18080/ids-test", timeout=3) as response:
            print(f"HTTP test returned {response.status}.")

        print("Connecting to 30 localhost TCP ports for the scan rule...")
        for port in range(19000, 19030):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
                connection.settimeout(0.2)
                connection.connect_ex(("127.0.0.1", port))
        print("Local traffic tests complete.")
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)


if __name__ == "__main__":
    main()