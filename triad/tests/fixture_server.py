"""Local fixture HTTP server that simulates a realistically misconfigured,
vulnerable target. Mirrors data/demo/web_fixture.json so LIVE scans and DEMO
scans produce the same finding set through the same engine."""
import http.server
import threading

PAGE = (
    "HTTP/1.1 200 OK\r\n"
    "Server: Apache/2.4.49 (Unix)\r\n"
    "X-Powered-By: PHP/7.4.3\r\n"
    "Set-Cookie: session=abc123; Path=/\r\n"
    "Access-Control-Allow-Origin: *\r\n"
    "Content-Type: text/html; charset=UTF-8\r\n"
    "\r\n"
    "<html><head><title>Files</title></head><body><h1>Index of /</h1></body></html>"
).replace("\r\n", "\n")

ROUTES = {
    "/": ("200 OK", [
        ("Server", "Apache/2.4.49 (Unix)"),
        ("X-Powered-By", "PHP/7.4.3"),
        ("Set-Cookie", "session=abc123; Path=/"),
        ("Access-Control-Allow-Origin", "*"),
        ("Content-Type", "text/html; charset=UTF-8"),
    ], "<html><head><title>Files</title></head><body><h1>Index of /</h1>"
       "<!-- Warning: mysql_query(): Access denied for user 'root'@'localhost' "
       "in /var/www/html/db.php on line 12 --></body></html>"),
    "/.git/HEAD": ("200 OK", [("Content-Type", "text/plain")], "ref: refs/heads/main\n"),
    "/.git/config": ("200 OK", [("Content-Type", "text/plain")],
                     "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"),
    "/.env": ("200 OK", [("Content-Type", "text/plain")],
              "APP_NAME=demo\nAPP_KEY=base64:demo-not-a-real-key\nDB_PASSWORD=supersecret\n"),
    "/actuator": ("200 OK", [("Content-Type", "application/vnd.spring-boot.actuator.v3+json")],
        '{"_links":{"self":{"href":"http://fixture.local/actuator","templated":false},'
        '"env":{"href":"http://fixture.local/actuator/env","templated":false}}}'),
    "/phpinfo.php": ("200 OK", [("Content-Type", "text/html; charset=UTF-8")],
                     '<html><body><h1 class="p">PHP Version 7.4.3</h1></body></html>'),
    "/manager/html": ("401 Unauthorized", [("Content-Type", "text/html;charset=utf-8")],
        "<html><h1>401 Unauthorized</h1><hr/><b>Apache Tomcat/9.0.65</b></html>"),
    "/jenkins/": ("200 OK", [("Content-Type", "text/html; charset=utf-8")],
        '<html><head><title>Sign in [Jenkins]</title></head><body>Jenkins ver. 2.401.1</body></html>'),
    "/swagger-ui/": ("200 OK", [("Content-Type", "text/html")],
        '<html><head><title>Swagger UI</title></head></html>'),
    "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd": ("200 OK", [("Content-Type", "text/plain")],
        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"),
}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        route = ROUTES.get(self.path.split("?")[0])
        if route is None:
            self.send_response(404)
            self.end_headers()
            return
        status, headers, body = route
        body_bytes = body.encode()
        self.send_response(int(status.split()[0]))
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

    def log_message(self, *args):
        pass


def start_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


if __name__ == "__main__":  # pragma: no cover
    srv, url = start_server()
    print(f"fixture server on {url}")
    try:
        threading.Event().wait()
    finally:
        srv.shutdown()
