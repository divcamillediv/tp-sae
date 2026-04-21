#!/bin/bash

# Exit script immediately if a command fails
set -e

echo "==========================================="
echo "   Ansible Download & Installation Script  "
echo "==========================================="

# 1. Update package lists and install dependencies
apt-get update -y
apt-get install -y python3 python3-pip python3-venv

# 2. Set up a Python Virtual Environment
# (This prevents Ansible from conflicting with system Python packages)
ENV_DIR="$HOME/ansible-env"
echo ">> Creating Python virtual environment at $ENV_DIR..."
python3 -m venv "$ENV_DIR"

# 3. Activate the environment
source "$ENV_DIR/bin/activate"

# 4. Download and Install Ansible
echo ">> Downloading and installing Ansible via pip..."
pip install --upgrade pip
pip install ansible

echo "==========================================="
echo " Installation Complete!"
echo "==========================================="
echo "To start using Ansible, activate your environment by running:"
echo "source $ENV_DIR/bin/activate"
echo ""
echo "Verifying installation:"
ansible --version