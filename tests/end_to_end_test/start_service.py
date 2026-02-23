import subprocess
import os

def main():
    # The ssh-ca-server binary should be in the PATH
    server_path = os.environ.get("SSH_CA_SERVER")
    if not server_path:
        raise Exception("SSH_CA_SERVER environment variable not set")

    server_process = subprocess.Popen([server_path, "-c", "/etc/ssh_ca/config.toml"])

    try:
        # Wait for the process to complete, or add other logic as needed
        server_process.wait()
    except KeyboardInterrupt:
        # Terminate the process if the script is interrupted
        server_process.terminate()
        server_process.wait()

if __name__ == "__main__":
    main()
