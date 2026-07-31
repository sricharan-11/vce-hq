#!/bin/bash
sudo usermod -aG docker $USER
sg docker -c "cd ~/VCE-HQ && git pull && bash deploy.sh"
