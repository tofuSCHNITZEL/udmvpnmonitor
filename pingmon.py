#!/usr/bin/env python3
"""
Ping Monitor Script

This script monitors a host by pinging it continuously. If the ping fails
for more than 3 consecutive times, it executes a specified SSH command
to a remote host.

On first run, the script will prompt for:
- Target host to ping
- SSH target host
- SSH username and password

All configuration is stored securely with salted encryption and reused on subsequent runs.

Dependencies:
- paramiko (for SSH functionality)
- cryptography (for credential encryption)

Install with: pip install paramiko cryptography
"""

import subprocess
import time
import sys
import logging
from typing import Optional, Tuple
import paramiko
import json
import os
import getpass
from cryptography.fernet import Fernet
import base64
import platform
import ipaddress
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Configuration
TARGET_HOST = None  # Will be loaded from credentials file or prompted
SSH_HOST = None  # Will be loaded from credentials file or prompted
SSH_PORT = 22
SSH_USERNAME = None  # Will be loaded from credentials file or prompted
SSH_PASSWORD = None  # Will be loaded from credentials file or prompted
SSH_KEY_PATH = None  # Path to private key file (if using key-based auth)
SSH_COMMAND = "killall charon"  # Command to execute via SSH

PING_INTERVAL = 5  # Seconds between pings
MAX_CONSECUTIVE_FAILURES = 3
PING_TIMEOUT = 3  # Ping timeout in seconds

# Configuration file
CONFIG_FILE = "ping_monitor_config.json"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("ping_monitor.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)


def ping_host(host: str, timeout: int = 3) -> bool:
    """
    Ping a host and return True if successful, False otherwise.

    Args:
        host: The hostname or IP address to ping
        timeout: Timeout in seconds for the ping command

    Returns:
        bool: True if ping successful, False otherwise
    """
    try:
        # Use platform-appropriate ping command
        if sys.platform.startswith("win"):
            # Windows ping command
            cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), host]
        else:
            # Unix/Linux ping command
            cmd = ["ping", "-c", "1", "-W", str(timeout), host]

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 2
        )

        return result.returncode == 0

    except subprocess.TimeoutExpired:
        logger.warning(f"Ping to {host} timed out")
        return False
    except Exception as e:
        logger.error(f"Error pinging {host}: {e}")
        return False


def generate_key(salt: bytes) -> bytes:
    """Generate a key for encryption based on machine-specific information and salt."""
    machine_info = f"{platform.node()}-{platform.system()}-{platform.machine()}"

    # Use PBKDF2 for key derivation with salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,  # Recommended minimum iterations
    )

    key = base64.urlsafe_b64encode(kdf.derive(machine_info.encode()))
    return key


def generate_salt() -> bytes:
    """Generate a random salt for key derivation."""
    return secrets.token_bytes(16)  # 16 bytes = 128 bits salt


def validate_host(host: str) -> bool:
    """
    Validate if a string is a valid IP address or hostname.

    Args:
        host: The host string to validate

    Returns:
        bool: True if valid IP or hostname, False otherwise
    """
    if not host:
        return False

    # Try to parse as IP address
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    # Try to validate as hostname
    # Check if hostname is valid format
    if len(host) > 253:
        return False

    # Check each label in the hostname
    labels = host.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        # Check for valid characters (letters, digits, hyphens)
        # Hyphens cannot be at start or end
        if not all(c.isalnum() or c == "-" for c in label):
            return False
        if label.startswith("-") or label.endswith("-"):
            return False

    return True


def save_credentials(
    target_host: str, ssh_host: str, username: str, password: str
) -> None:
    """Save configuration and SSH credentials to an encrypted file."""
    try:
        # Generate a random salt
        salt = generate_salt()
        key = generate_key(salt)
        fernet = Fernet(key)

        credentials = {
            "target_host": target_host,
            "ssh_host": ssh_host,
            "username": username,
            "password": password,
        }

        encrypted_data = fernet.encrypt(json.dumps(credentials).encode())

        # Store salt + encrypted data
        file_data = {
            "salt": base64.b64encode(salt).decode("utf-8"),
            "data": base64.b64encode(encrypted_data).decode("utf-8"),
        }

        with open(CONFIG_FILE, "w") as f:
            json.dump(file_data, f)

        # Set file permissions to be readable only by the current user
        if not sys.platform.startswith("win"):
            os.chmod(CONFIG_FILE, 0o600)

        logger.info("Configuration and credentials saved successfully")

    except Exception as e:
        logger.error(f"Error saving credentials: {e}")
        raise


def load_credentials() -> (
    Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]
):
    """Load configuration and SSH credentials from encrypted file."""
    try:
        if not os.path.exists(CONFIG_FILE):
            return None, None, None, None

        with open(CONFIG_FILE, "r") as f:
            file_data = json.load(f)

        # Extract salt and encrypted data
        salt = base64.b64decode(file_data["salt"])
        encrypted_data = base64.b64decode(file_data["data"])

        key = generate_key(salt)
        fernet = Fernet(key)

        decrypted_data = fernet.decrypt(encrypted_data)
        credentials = json.loads(decrypted_data.decode())

        return (
            credentials.get("target_host"),
            credentials.get("ssh_host"),
            credentials.get("username"),
            credentials.get("password"),
        )

    except Exception as e:
        logger.error(f"Error loading credentials: {e}")
        return None, None, None, None


def prompt_for_credentials() -> Tuple[str, str, str, str]:
    """Prompt user for configuration and SSH credentials."""
    print("\nConfiguration not found. Please enter the required information:")
    print("(Configuration will be saved securely for future use)")

    # Validate target host
    while True:
        target_host = input(
            "Target host to ping (IP or hostname, e.g., 192.168.1.1 or server.local): "
        ).strip()
        if not target_host:
            print("Error: Target host cannot be empty. Please try again.")
            continue
        if not validate_host(target_host):
            print(
                "Error: Invalid IP address or hostname format. Please enter a valid IP (e.g., 192.168.1.1) or hostname (e.g., server.local)."
            )
            continue
        break

    # Validate SSH host
    while True:
        ssh_host = input(
            "SSH target host (IP or hostname, e.g., 10.0.0.1 or ssh-server.local): "
        ).strip()
        if not ssh_host:
            print("Error: SSH host cannot be empty. Please try again.")
            continue
        if not validate_host(ssh_host):
            print(
                "Error: Invalid IP address or hostname format. Please enter a valid IP (e.g., 10.0.0.1) or hostname (e.g., ssh-server.local)."
            )
            continue
        break

    # Validate username
    while True:
        username = input("SSH Username: ").strip()
        if not username:
            print("Error: Username cannot be empty. Please try again.")
            continue
        break

    # Validate password
    while True:
        password = getpass.getpass("SSH Password: ")
        if not password:
            print("Error: Password cannot be empty. Please try again.")
            continue
        break

    return target_host, ssh_host, username, password


def get_configuration() -> Tuple[str, str, str, str]:
    """Get configuration and SSH credentials from file or prompt user."""
    # Try to load existing configuration
    target_host, ssh_host, username, password = load_credentials()

    if target_host and ssh_host and username and password:
        logger.info("Using saved configuration and credentials")
        return target_host, ssh_host, username, password

    # If no saved configuration, prompt user
    logger.info("No saved configuration found")
    target_host, ssh_host, username, password = prompt_for_credentials()

    # Save the configuration for future use
    save_credentials(target_host, ssh_host, username, password)

    return target_host, ssh_host, username, password


def execute_ssh_command(
    host: str,
    username: str,
    command: str,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    port: int = 22,
) -> bool:
    """
    Execute a command on a remote host via SSH.

    Args:
        host: SSH target host
        username: SSH username
        command: Command to execute
        password: SSH password (optional if using key-based auth)
        key_path: Path to private key file (optional)
        port: SSH port number

    Returns:
        bool: True if command executed successfully, False otherwise
    """
    ssh_client = None
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy)

        # Connect using password or key-based authentication
        if key_path:
            logger.info(f"Connecting to {host} using key authentication")
            ssh_client.connect(
                hostname=host,
                port=port,
                username=username,
                key_filename=key_path,
                timeout=10,
            )
        elif password:
            logger.info(f"Connecting to {host} using password authentication")
            ssh_client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=10,
                look_for_keys=False,
                allow_agent=False,
            )
        else:
            logger.error("No authentication method specified (password or key)")
            return False

        # Execute the command
        logger.info(f"Executing command: {command}")
        stdin, stdout, stderr = ssh_client.exec_command(command)

        # Get command output
        output = stdout.read().decode("utf-8").strip()
        error = stderr.read().decode("utf-8").strip()
        exit_code = stdout.channel.recv_exit_status()

        if exit_code == 0:
            if output:
                logger.info(f"Command output: {output}")
        else:
            logger.error(f"SSH command failed with exit code {exit_code}")
            if error:
                logger.error(f"Command error: {error}")

        return exit_code == 0

    except paramiko.AuthenticationException:
        logger.error(f"SSH authentication failed for {username}@{host}")
        return False
    except paramiko.SSHException as e:
        logger.error(f"SSH connection error: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during SSH execution: {e}")
        return False
    finally:
        if ssh_client:
            ssh_client.close()


def main():
    """Main monitoring loop."""
    logger.info("Starting ping monitor...")

    # Get configuration and credentials (will prompt if not saved)
    try:
        target_host, ssh_host, ssh_username, ssh_password = get_configuration()
    except (KeyboardInterrupt, EOFError):
        logger.info("Configuration input cancelled by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error getting configuration: {e}")
        sys.exit(1)

    logger.info(f"Target host: {target_host}")
    logger.info(f"SSH host: {ssh_host}")
    logger.info(f"Ping interval: {PING_INTERVAL} seconds")
    logger.info(f"Max consecutive failures: {MAX_CONSECUTIVE_FAILURES}")

    consecutive_failures = 0

    try:
        while True:
            if ping_host(target_host, PING_TIMEOUT):
                if consecutive_failures > 0:
                    logger.info(
                        f"Ping to {target_host} successful - resetting failure count"
                    )
                    consecutive_failures = 0
                else:
                    logger.debug(f"Ping to {target_host} successful")
            else:
                consecutive_failures += 1
                logger.warning(
                    f"Ping to {target_host} failed (failure #{consecutive_failures})"
                )

                if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                    logger.critical(
                        f"Ping failed {consecutive_failures} consecutive times - "
                        f"executing SSH command"
                    )

                    success = execute_ssh_command(
                        host=ssh_host,
                        username=ssh_username,
                        command=SSH_COMMAND,
                        password=ssh_password,
                        key_path=SSH_KEY_PATH,
                        port=SSH_PORT,
                    )

                    if success:
                        logger.info("SSH command executed successfully")
                        # Reset counter after successful SSH execution
                        consecutive_failures = 0
                    else:
                        logger.error("SSH command execution failed")

            # Wait before next ping
            time.sleep(PING_INTERVAL)

    except KeyboardInterrupt:
        logger.info("Monitoring stopped by user")
    except Exception as e:
        logger.error(f"Unexpected error in main loop: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Validate static configuration before starting
    if not SSH_COMMAND:
        logger.error("SSH_COMMAND not configured")
        sys.exit(1)

    main()
