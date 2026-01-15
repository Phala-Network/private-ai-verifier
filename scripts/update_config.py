import os
import requests

CONFIG_URL = "https://raw.githubusercontent.com/tinfoilsh/confidential-model-router/refs/heads/main/config.yml"
CONFIG_PATH = "config/tinfoil_config.yml"


def update_config():
    print(f"Updating Tinfoil configuration from {CONFIG_URL}...")
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    response = requests.get(CONFIG_URL)
    response.raise_for_status()
    with open(CONFIG_PATH, "wb") as f:
        f.write(response.content)
    print(f"Successfully updated configuration to {CONFIG_PATH}")


if __name__ == "__main__":
    update_config()
