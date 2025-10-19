# we need to log the ip address, username and passwords into a file 

import logging
import socket
import paramiko
from logging.handlers import RotatingFileHandler
import datetime
import random
import threading
import time
from pathlib import Path

# constants for banner and file paths
SSH_BANNER = "SSH-2.0-HoneyPawt_Meow_1.0"

# get base directory of where user is running honeypy from
base_dir = Path(__file__).parent
# source creds_audits.log & cmd_audits.log file path
server_key_dir = base_dir / 'ssh_honeypy' / 'static'
server_key = server_key_dir / 'server.key'

creds_audits_log_local_file_path = base_dir / 'audits.log'
cmd_audits_log_local_file_path = base_dir / 'cmd_audits.log'

# SSH server host key for authentication
try:
    if server_key.exists():
        print(f"Loading existing SSH host key from {server_key}")
        host_key = paramiko.RSAKey(filename=str(server_key))
    else:
        print(f"Creating new SSH host key at {server_key}")
        server_key_dir.mkdir(parents=True, exist_ok=True)
        host_key = paramiko.RSAKey.generate(2048)
        host_key.write_private_key_file(str(server_key))
        # save public key
        with open(f"{server_key}.pub", 'w') as pub_file:
            pub_file.write(f"{host_key.get_name()} {host_key.get_base64()}")
        print(f"SSH key pair created: {server_key} and {server_key}.pub")
except Exception as e:
    print(f"Warning: Could not load/create key file ({e}). Using temporary key.")
    host_key = paramiko.RSAKey.generate(2048)

# logging format for clean output
logging_format = logging.Formatter('%(message)s')

# funnel logger for general events
funnel_logger = logging.getLogger('HoneyPawtLogger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler(cmd_audits_log_local_file_path, maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

# credentials logger captures IP address, username, password
creds_logger = logging.getLogger('PawPrintLogger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler(creds_audits_log_local_file_path, maxBytes=2000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)

# SSH server class establishes the options for the SSH server
class HoneyPawtServer(paramiko.ServerInterface):

    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def get_allowed_auths(self, username):
        return "password"
    
    def check_auth_password(self, username, password):
        # log every login attempt for security monitoring
        funnel_logger.info(f'Curious cat {self.client_ip} tried to sneak in with username: {username}, password: {password}')
        creds_logger.info(f'Client {self.client_ip} attempted connection with username: {username}, password: {password}')
        
        # check if specific credentials are required
        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password:
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED
        else:
            return paramiko.AUTH_SUCCESSFUL  # honeypot mode accepts all credentials
    
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True
    
    def check_channel_exec_request(self, channel, command):
        command = str(command)
        return True

def honey_shell(channel, client_ip):
    # send welcome banner to make it look legit
    welcome_banner = """
Welcome to HoneyCorp Cat Server

System Status: OPERATIONAL

Last Maintenance: 2025-10-18

Please use authorized credentials only.

    """
    channel.send(welcome_banner.encode())
    channel.send(b"cat@honeypawt:~$ ")
    
    # fake system files and directories
    fake_files = [b'catnip.conf', b'litterbox.log', b'honey_pot.jar', b'mouse_db.sql', b'yarn_ball.txt', b'fish_treats.dat']
    current_dir = b'/home/cat'
    command_history = []

    command = b""
    while True:
        char = channel.recv(1)
        
        if not char:
            channel.close()
            break
        
        # handle backspace character
        if char == b'\x7f':
            if command:
                command = command[:-1]
                channel.send(b'\b \b')
            continue
        
        # handle tab completion
        if char == b'\t':
            suggestions = [b'ls', b'pwd', b'whoami', b'cat', b'exit', b'purr', b'meow', b'scratch']
            matches = [cmd for cmd in suggestions if cmd.startswith(command.strip())]
            if len(matches) == 1:
                remaining = matches[0][len(command.strip()):]
                command += remaining
                channel.send(remaining)
            continue
        
        channel.send(char)  # echo character back to user
        command += char
        
        # emulate shell commands when enter is pressed
        if char == b"\r" or char == b'\n':
            command_str = command.strip()
            
            # log every command attempt
            funnel_logger.info(f'Cat {client_ip} scratched command: {command_str.decode("utf-8", errors="ignore")}')
            
            if command_str == b'exit':
                response = b"\nMeow! Thanks for visiting HoneyPawt!\n"
                channel.send(response)
                channel.close()
                break
                
            elif command_str == b'pwd':
                response = b"\n" + current_dir + b"\r\n"
                
            elif command_str == b'whoami':
                response = b"\nhoney-cat\r\n"
                
            elif command_str == b"id":
                response = b'\nuid=1001(honey-cat) gid=1001(cats) groups=1001(cats),27(honey-lovers)\r\n'
                
            elif command_str == b'ls' or command_str.startswith(b'ls '):
                file_list = b'\n' + b'   '.join(fake_files) + b'\r\n'
                response = file_list
                
            elif command_str.startswith(b"cat "):
                filename = command_str[4:].strip()
                if filename == b'catnip.conf':
                    response = b'\n# HoneyCorp Catnip Configuration\nserver=catnip.honeycorp.com\nport=9999\nfreshness=premium\n# Secret stash: meow.honeypawt.com\r\n'
                elif filename == b'honey_pot.jar':
                    response = b'\nSweet, sticky honey that traps curious cats!\nIngredients: 100% pure honey, 0% escape routes\nWarning: May cause prolonged purring\r\n'
                elif filename == b'mouse_db.sql':
                    response = b'\nSELECT * FROM mice WHERE location="basement";\njerry: basement_corner_1\nsqueaky: under_fridge\nnibbles: pantry_shelf\r\n'
                elif filename == b'yarn_ball.txt':
                    response = b'\nRed yarn ball - location: living room\nBlue yarn ball - location: bedroom\nRainbow yarn ball - location: CLASSIFIED\r\n'
                else:
                    response = b'\ncat: ' + filename + b': No such file or directory (maybe the mice ate it?)\r\n'
                    
            elif command_str == b"purr":
                response = b'\n*purrrrrrrrrr* The honey-cat is happy!\r\n'
                
            elif command_str == b"meow":
                response = b'\nMeow! Welcome to the honey trap, curious visitor!\r\n'
                
            elif command_str == b"scratch":
                response = b'\n*scratch scratch* You found some interesting log files!\r\n'
                
            elif command_str == b"ps" or command_str == b"ps aux":
                fake_processes = b'\nPID TTY      TIME CMD\n1337 pts/0   00:00:01 catnip-daemon\n2020 pts/0   00:00:00 honey-collector\n3030 pts/0   00:00:02 mouse-tracker\n4040 pts/0   00:00:01 yarn-guardian\r\n'
                response = fake_processes
                
            elif command_str == b"netstat" or command_str.startswith(b"netstat"):
                fake_netstat = b'\nActive Honey Connections\nProto Recv-Q Send-Q Local Address           Foreign Address         State\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\ntcp        0      0 192.168.1.100:9999      0.0.0.0:*               LISTEN (catnip port)\r\n'
                response = fake_netstat
                
            elif command_str == b"uname" or command_str == b"uname -a":
                response = b'\nLinux honeypawt 5.4.0-cats #meow-Ubuntu SMP Fri Purr 9 22:49:44 UTC 2021 x86_64 x86_64 x86_64 GNU/Cat\r\n'
                
            elif command_str == b"date":
                current_time = datetime.datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y").encode()
                response = b'\n' + current_time + b' (Feeding time!)\r\n'
                
            elif command_str == b"history":
                history_output = b'\nYour paw prints in the honey:\n'
                for i, cmd in enumerate(command_history[-10:], 1):
                    history_output += f"  {i}  {cmd.decode('utf-8', errors='ignore')}\n".encode()
                response = history_output + b'\r\n'
                
            elif command_str.startswith(b"cd "):
                new_dir = command_str[3:].strip()
                if new_dir == b"..":
                    current_dir = b'/home' if current_dir == b'/home/cat' else b'/home/cat'
                elif new_dir == b"/":
                    current_dir = b'/'
                elif new_dir == b"litterbox":
                    current_dir = b'/home/cat/litterbox'
                    response = b'\nWelcome to the litterbox! (Please clean up after yourself)\r\n'
                else:
                    current_dir = b'/home/cat/' + new_dir
                response = b'\n'
                
            elif command_str == b"help":
                help_text = b'\nHoneyPawt Commands:\nls, pwd, whoami, id, cat, purr, meow, scratch, ps, netstat, uname, date, history, cd, exit\nSpecial: Try "cat catnip.conf" or "meow" for surprises!\r\n'
                response = help_text
                
            elif command_str.startswith(b"sudo "):
                response = b'\n[sudo] password for honey-cat: '
                channel.send(response)
                password = b""
                while True:
                    pwd_char = channel.recv(1)
                    if pwd_char == b'\r' or pwd_char == b'\n':
                        break
                    password += pwd_char
                # log the sudo attempt and password
                funnel_logger.info(f"Sneaky cat {client_ip} tried sudo with password: {password.decode('utf-8', errors='ignore')}")
                response = b'\nSorry, only the head cat has sudo privileges! Try bringing tuna instead.\r\n'
                
            elif len(command_str) == 0:
                response = b''
                
            else:
                response = b"\n*confused meow* Command not found: " + command_str + b" (Maybe try 'help'?)\r\n"
            
            # add command to history if it's not empty
            if command_str and len(command_str) > 0:
                command_history.append(command_str)
                
            if response:
                channel.send(response)
            channel.send(b"cat@honeypawt:~$ ")
            command = b""

def cat_handler(client, addr, username, password, tarpit=False):
    client_ip = addr[0]
    print(f"Curious cat from {client_ip} stepped into the honey trap!")
    
    try:
        # initialize transport object using socket connection from client
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        
        # create SSH server instance and start server
        server = HoneyPawtServer(client_ip=client_ip, input_username=username, input_password=password)
        transport.add_server_key(host_key)
        transport.start_server(server=server)
        
        # establish encrypted tunnel for communication
        channel = transport.accept(100)
        
        if channel is None:
            print("No channel was opened - the cat got away!")
            return
        
        standard_banner = "Connecting to HoneyCorp Cat Server...\n"
        
        try:
            # tarpit mode sends endless banner to waste attacker time
            if tarpit:
                endless_banner = standard_banner * 50
                for char in endless_banner:
                    channel.send(char.encode())
                    time.sleep(5)
            else:
                channel.send(standard_banner.encode())
            
            # start interactive shell session
            honey_shell(channel, client_ip=client_ip)
            
        except Exception as error:
            print(f"Shell error: {error}")
            
    except Exception as error:
        print(f"Transport error: {error}")
        print("Exception occurred!")
    
    finally:
        try:
            transport.close()
        except Exception:
            pass
        
        client.close()
        print(f"Cat {client_ip} left the honey trap")

def honeypawt_server(address, port, username, password, tarpit=False):
    # create TCP socket and bind to port
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))
    
    # listen for up to 100 concurrent connections
    socks.listen(100)
    print(f"HoneyPawt server is purring on port {port}... waiting for curious cats!")
    
    while True:
        try:
            # accept connection from client
            client, addr = socks.accept()
            # start new thread to handle client connection
            cat_thread = threading.Thread(target=cat_handler, args=(client, addr, username, password, tarpit))
            cat_thread.start()
            
        except Exception as error:
            print("Exception - Could not catch this curious cat!")
            print(error)

# entry point for running the honeypot directly
if __name__ == "__main__":
    print("Starting HoneyPawt - Where curious cats get stuck!")
    honeypawt_server('0.0.0.0', 2222, None, None)