from flask import Flask, render_template, request
from database import get_alerts_by_filter
import threading
from config import WEB_HOST, WEB_PORT

app = Flask(__name__)

@app.route("/")
def index():
    src_ip = request.args.get('src_ip')
    dst_ip = request.args.get('dst_ip')
    attack_type = request.args.get('attack_type')
    start_time = request.args.get('start_time')
    end_time = request.args.get('end_time')

    alerts = get_alerts_by_filter(src_ip, dst_ip, attack_type, start_time, end_time)
    return render_template("index.html", alerts=alerts)

def start_web():
    thread = threading.Thread(target=lambda: app.run(debug=False, host=WEB_HOST, port=WEB_PORT, use_reloader=False))
    thread.start()
