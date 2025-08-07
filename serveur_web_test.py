from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import logging

class WebSnifferHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        logging.info("==== Requête GET ====")
        logging.info("Path: %s", self.path)
        logging.info("Headers:\n%s", str(self.headers))

        html = """
        <html>
        <head><title>Test HTTP</title></head>
        <body>
            <h2>Formulaire GET</h2>
            <form method="GET" action="/">
                <input type="text" name="search" placeholder="Recherche...">
                <input type="submit" value="Envoyer GET">
            </form>

            <h2>Formulaire POST</h2>
            <form method="POST" action="/">
                Nom: <input type="text" name="nom"><br>
                Email: <input type="email" name="email"><br>
                Message: <textarea name="message"></textarea><br>
                <input type="submit" value="Envoyer POST">
            </form>
        </body>
        </html>
        """

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        fields = urllib.parse.parse_qs(post_data.decode())

        logging.info("==== Requête POST ====")
        logging.info("Path: %s", self.path)
        logging.info("Headers:\n%s", str(self.headers))
        logging.info("Données POST :\n%s", str(fields))

        response = "<html><body><h1>POST reçu</h1><pre>"
        for key, value in fields.items():
            response += f"{key}: {value[0]}\n"
        response += "</pre><a href='/'>Retour</a></body></html>"

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(response.encode())

def run(port=8080):
    logging.basicConfig(level=logging.INFO)
    server_address = ('', port)
    httpd = HTTPServer(server_address, WebSnifferHandler)
    print(f"🌐 Serveur en écoute sur http://localhost:{port}")
    httpd.serve_forever()

if __name__ == '__main__':
    try:
        run(port=9000)  # ou 80 si tu veux, avec sudo
    except PermissionError:
        print("❌ Permission refusée : utilise sudo pour le port 80, ou un port >1024.")
