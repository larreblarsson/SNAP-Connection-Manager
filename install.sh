#!/usr/bin/env 
set -e
curl -sL https://larreblarsson.github.io/SCARPA-Connection-Manager/public.key | sudo gpg --dearmor -o /usr/share/keyrings/SCARPA-Connection-Manager-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/SCARPA-Connection-Manager-keyring.gpg] https://larreblarsson.github.io/SCARPA-Connection-Manager stable main" | sudo tee /etc/apt/sources.list.d/SCARPA-Connection-Manager.list
sudo apt update
sudo apt install scarpa-connection-manager
