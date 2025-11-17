#!/usr/bin/env 
set -e
curl -sL https://larreblarsson.github.io/SNAP-Connection-Manager/public.key | sudo gpg --dearmor -o /usr/share/keyrings/SNAP-Connection-Manager-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/SNAP-Connection-Manager-keyring.gpg] https://larreblarsson.github.io/SNAP-Connection-Manager stable main" | sudo tee /etc/apt/sources.list.d/SNAP-Connection-Manager.list
sudo apt update
sudo apt install snap-connection-manager
