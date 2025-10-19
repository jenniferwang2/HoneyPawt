# Import library dependencies.
from flask import Flask, render_template, request, redirect, url_for
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Logging Format
logging_format = logging.Formatter('%(asctime)s %(message)s')

base_dir = Path(__file__).parent
log_files_dir = base_dir / 'log_files'  # Create log_files directory path
log_files_dir.mkdir(exist_ok=True)  # Create directory if it doesn't exist
http_audits_log_local_file_path = log_files_dir / 'http_audit.log'  # Updated path

# HTTP Logger
funnel_logger = logging.getLogger('HTTPLogger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler(http_audits_log_local_file_path, maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

def baseline_web_honeypot(input_username="admin", input_password="deeboodah"):
    app = Flask(__name__)

    @app.route('/')
    def index():
        ip_address = request.remote_addr
        funnel_logger.info(f'Client {ip_address} accessed main page')
        return render_template('wp-admin.html')

    @app.route('/wp-admin-login', methods=['POST'])
    def login():
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        ip_address = request.remote_addr

        # Log every login attempt
        funnel_logger.info(f'Client {ip_address} attempted login with username: {username}, password: {password}')

        if username == input_username and password == input_password:
            return '<h1>Login Successful!</h1><p>Welcome to the admin panel.</p>'
        else:
            return '<h1>Login Failed</h1><p>Invalid username or password. <a href="/">Try again</a></p>'
        
    return app

def run_app(port=8080, input_username="admin", input_password="deeboodah"):
    app = baseline_web_honeypot(input_username, input_password)
    print(f"Starting web honeypot on port {port}")
    print(f"Access it at: http://localhost:{port}")
    print(f"Logging to: {http_audits_log_local_file_path}")  # Show where logs are going
    app.run(debug=True, port=port, host="0.0.0.0")
    return app

if __name__ == "__main__":
    run_app()
