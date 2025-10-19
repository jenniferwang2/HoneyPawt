# HoneyPawt

![CatMouseDevious](Cat%20and%20Mouse%20Image.png)

## What is a Honeypot?

A honeypot is a decoy host or server that emulates legitimate business infrastructure to attract and monitor malicious activity. It's designed to appear as a valuable target while actually serving as a trap for attackers.

### What Honeypots Can Impersonate:
- Employee and customer databases
- Jump hosts and bastion hosts into corporate environments  
- Workstations and endpoints
- Files and canary tokens
- Web applications and services

Honeypots are a key component of **deception engineering** - a cybersecurity domain focused on collecting threat intelligence by luring attackers into controlled environments. There are many different types and implementations.

### Types of Honeypot Systems:
- **Honeypot**: A singular decoy system
- **Honeynet**: Multiple honeypots working together to simulate a complete network environment

Attackers may attempt to move laterally, escalate privileges, and perform various malicious activities - all while being monitored and logged.

## HoneyPawt Components

HoneyPawt is a modular honeypot system with multiple components to capture different types of attacks:

### 1. SSH Honeypot (`ssh_honeypawt.py`)
A cat-themed SSH honeypot that captures SSH login attempts and provides an interactive fake shell environment.

### 2. Web Honeypot (`web_honeypot.py`)  
A Flask-based web honeypot that simulates a WordPress admin login page to capture web-based credential theft attempts.

## File Structure
```
HoneyPawt/
├── ssh_honeypawt.py              # SSH honeypot module
├── web_honeypot.py               # Web honeypot module
├── README.md                     # This file
├── .gitignore                    # Git ignore file (excludes keys and logs)
├── templates/
│   └── wp-admin.html            # WordPress login page template
├── ssh_honeypy/
│   └── static/
│       ├── server.key           # SSH private key (auto-generated)
│       └── server.key.pub       # SSH public key (auto-generated)
├── log_files/
│   └── http_audit.log          # Web honeypot logs
├── audits.log                   # SSH credential logs
├── cmd_audits.log              # SSH command logs
└── systemd/
    └── honeypy.service         # Systemd service file
```

## Prerequisites

### Required Dependencies
```bash
pip3 install paramiko flask
```

### System Requirements
- Python 3.6+
- Available ports (default: 2222 for SSH, 8080 for web)
- Write permissions for log files

## Installation & Setup

### 1. Clone/Download HoneyPawt
```bash
git clone <repository-url>
cd HoneyPawt
```

### 2. Install Dependencies
```bash
pip3 install paramiko flask
```

### 3. Create Required Directories
```bash
mkdir -p templates ssh_honeypy/static log_files
```

### 4. Create WordPress Template (if not included)
The web honeypot requires a WordPress login template at `templates/wp-admin.html`.

## Usage

### SSH Honeypot

#### Basic Usage
```bash
python3 ssh_honeypawt.py
```

**Expected Output:**
```
Starting HoneyPawt - Where curious cats get stuck!
HoneyPawt server is purring on port 2222... waiting for curious cats!
```

#### Advanced Configuration
Edit `ssh_honeypawt.py` line 306 to customize:
```python
# Accept any credentials (default honeypot mode)
honeypawt_server('0.0.0.0', 2222, None, None)

# Require specific credentials
honeypawt_server('0.0.0.0', 2222, 'admin', 'password123')

# Enable tarpit mode (slow responses to waste attacker time)
honeypawt_server('0.0.0.0', 2222, None, None, tarpit=True)

# Custom port
honeypawt_server('0.0.0.0', 3333, None, None)
```

### Web Honeypot

#### Basic Usage
```bash
python3 web_honeypot.py
```

**Expected Output:**
```
Starting web honeypot on port 8080
Access it at: http://localhost:8080
Logging to: /path/to/HoneyPawt/log_files/http_audit.log
```

#### Custom Configuration
```python
# Custom port and credentials
run_app(port=9090, input_username="root", input_password="toor")
```

## Testing Your Honeypots

### SSH Honeypot Testing

#### 1. Remove Conflicting SSH Keys
```bash
ssh-keygen -R "[localhost]:2222"
```

#### 2. Test Local Connection
```bash
# Skip host key verification (recommended for testing)
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null testuser@localhost

# Or accept new host key when prompted
ssh -p 2222 anyusername@localhost
```

#### 3. Interactive Shell Commands
Once connected, try these commands:

**Basic Linux Commands:**
```bash
whoami          # Returns: honey-cat
pwd             # Returns: /home/cat
ls              # Shows fake files
id              # Shows fake user permissions
ps aux          # Shows cat-themed processes
netstat         # Shows fake network connections
uname -a        # Shows cat-themed system info
date            # Shows time with cat message
history         # Shows command history as "paw prints"
```

**File Operations:**
```bash
cat catnip.conf     # Fake configuration with hidden URLs
cat honey_pot.jar   # Honey trap description
cat mouse_db.sql    # Fake mouse database
cat yarn_ball.txt   # Yarn ball locations
```

**Cat-Themed Special Commands:**
```bash
purr            # Cat purring response
meow            # Cat greeting
scratch         # Find interesting files
```

**Directory Navigation:**
```bash
cd /            # Go to root
cd litterbox    # Special cat directory
cd ..           # Go up one directory
```

**Privilege Escalation Test:**
```bash
sudo su         # Prompts for password, then rejects with cat message
```

### Web Honeypot Testing

#### 1. Access the Login Page
Open your browser and navigate to:
```
http://localhost:8080
```

#### 2. Test Login Attempts
Try various username/password combinations:
- admin/admin
- root/password
- user/123456
- administrator/password123

#### 3. Check Successful Login
Use the correct credentials (default: admin/deeboodah) to see the success page.

### Remote Testing

#### Find Your IP Address
```bash
# On macOS/Linux
ifconfig | grep inet
hostname -I
```

#### Connect from Another Machine
```bash
# SSH Honeypot
ssh -p 2222 -o StrictHostKeyChecking=no username@YOUR_HONEYPOT_IP

# Web Honeypot
http://YOUR_HONEYPOT_IP:8080
```

## Log Analysis

### SSH Logs

#### Credential Logs (`audits.log`)
```
Client 127.0.0.1 attempted connection with username: admin, password: password123
Client 192.168.1.100 attempted connection with username: root, password: toor
Client 10.0.0.50 attempted connection with username: user, password: 123456
```

#### Command Logs (`cmd_audits.log`)
```
Curious cat 127.0.0.1 tried to sneak in with username: admin, password: secret
Cat 127.0.0.1 scratched command: ls
Cat 127.0.0.1 scratched command: cat catnip.conf
Sneaky cat 127.0.0.1 tried sudo with password: admin123
```

### Web Logs (`log_files/http_audit.log`)
```
2025-10-18 19:20:46,200 Client 127.0.0.1 accessed main page
2025-10-18 19:20:55,245 Client 127.0.0.1 attempted login with username: admin, password: password123
2025-10-18 19:21:03,112 Client 192.168.1.100 attempted login with username: root, password: toor
```

### Real-time Log Monitoring
```bash
# Monitor SSH credential attempts
tail -f audits.log

# Monitor SSH commands
tail -f cmd_audits.log

# Monitor web attempts
tail -f log_files/http_audit.log

# Monitor all logs simultaneously
tail -f audits.log cmd_audits.log log_files/http_audit.log
```

## Troubleshooting

### SSH Honeypot Issues

#### Host Key Verification Failed
```bash
# Remove conflicting keys
ssh-keygen -R "[localhost]:2222"
ssh-keygen -R "[YOUR_IP]:2222"

# Or connect with relaxed security
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null user@localhost
```

#### Transport Errors
- Ensure port 2222 is available: `lsof -i :2222`
- Check firewall settings
- Verify Paramiko installation: `pip3 show paramiko`

#### Permission Issues
```bash
# Make script executable
chmod +x ssh_honeypawt.py

# Check Python version
python3 --version  # Should be 3.6+
```

### Web Honeypot Issues

#### Port Already in Use (5000)
```bash
# Check what's using the port
lsof -i :5000

# On macOS, disable AirPlay Receiver:
# System Preferences → General → AirDrop & Handoff → Turn off AirPlay Receiver

# Or use different port in web_honeypot.py
run_app(port=8080)
```

#### Template Not Found
Ensure `templates/wp-admin.html` exists in the correct location.

#### No Logs Being Written
Check that the `log_files` directory exists and has write permissions:
```bash
mkdir -p log_files
chmod 755 log_files
```

## Production Deployment

### Running as System Service

#### 1. Create Service File
```bash
sudo cp systemd/honeypy.service /etc/systemd/system/
```

#### 2. Update Service Configuration
Edit `/etc/systemd/system/honeypy.service`:
```ini
[Unit]
Description=HoneyPawt SSH and Web Honeypot
After=network.target

[Service]
Type=simple
WorkingDirectory=/path/to/HoneyPawt
ExecStart=/usr/bin/python3 /path/to/HoneyPawt/ssh_honeypawt.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

#### 3. Enable and Start Service
```bash
sudo systemctl daemon-reload
sudo systemctl enable honeypy
sudo systemctl start honeypy
sudo systemctl status honeypy
```

### Log Rotation
Add to crontab for automatic log cleanup:
```bash
# Clean logs older than 7 days
0 0 * * * find /path/to/HoneyPawt -name "*.log*" -mtime +7 -delete
```

### Firewall Configuration
```bash
# Allow SSH honeypot port
sudo ufw allow 2222

# Allow web honeypot port
sudo ufw allow 8080
```

## Security Considerations

⚠️ **Important Security Notes:**

### Deployment Guidelines
- **Isolated Environment**: Deploy honeypots in isolated networks or VMs
- **No Production Systems**: Never run on systems with real data
- **Legal Compliance**: Ensure deployment complies with local laws
- **Monitoring**: Regularly monitor logs for threat intelligence
- **Data Protection**: Handle captured credentials responsibly

### Data Security
- Log files contain real attacker credentials and commands
- Implement proper access controls on log files
- Consider encrypting stored logs
- Rotate and archive logs regularly
- Follow data retention policies

### Network Security
- Use firewall rules to control honeypot access
- Consider rate limiting to prevent abuse
- Monitor network traffic to/from honeypots
- Isolate honeypots from production networks

## Architecture & Technology

### Technology Stack
- **Core**: Python 3.6+
- **SSH Implementation**: Paramiko
- **Web Framework**: Flask
- **Frontend**: HTML/CSS (Bootstrap-styled)
- **Logging**: Python logging with rotation
- **System Integration**: systemd services

### Modular Design
HoneyPawt uses a modular architecture where different attack vectors are handled by specialized components:

- **SSH Module**: Captures SSH-based attacks and command execution
- **Web Module**: Captures web-based credential theft
- **Logging System**: Centralized logging with rotation and formatting
- **Service Integration**: systemd service files for production deployment

### Scalability
- Multi-threaded connection handling
- Rotating log files prevent disk space issues
- Configurable ports and credentials
- Easy to deploy multiple instances

## Contributing

HoneyPawt is an educational project focused on cybersecurity research and threat intelligence gathering. 

### Development Guidelines
- Maintain realistic deception without being malicious
- Focus on educational value and threat research
- Follow responsible disclosure practices
- Test thoroughly before submitting changes

### Code Standards
- Python PEP 8 style guidelines
- Clear, concise comments
- Modular, maintainable code structure
- Comprehensive error handling

## Legal and Ethical Considerations

### Legal Compliance
- Ensure honeypot deployment complies with local laws
- Consider privacy implications of capturing attacker data
- Implement appropriate data handling and retention policies
- Consult legal counsel for production deployments

### Ethical Use
- Use honeypots for defensive purposes and research only
- Handle captured data responsibly and securely
- Respect attacker privacy when possible
- Share threat intelligence responsibly with the community

### Research Applications
- Threat intelligence gathering
- Attack pattern analysis
- Security awareness training
- Cybersecurity education and research

---

**Happy hunting! 🐱🍯**

*Remember: HoneyPawt is designed for educational purposes and cybersecurity research. Always deploy responsibly and in compliance with applicable laws and regulations.*

