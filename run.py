from App import create_app
from App.config import Config
import threading
import webview

app = create_app()

def run_flask():
    app.run(host=Config.FLASK_HOST, port=Config.FLASK_PORT, debug=False)

if __name__ == '__main__':
    threading.Thread(target=run_flask, daemon=True).start()
    webview.create_window("Douen SOC", "http://127.0.0.1:5000")
    webview.start(icon='./App/static/logo_icon_simple.ico')
