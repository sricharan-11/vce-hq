gcloud compute ssh instance-20260426-224222 --zone=us-central1-a --project=isolated-lab-for-testing -- 'sudo usermod -aG docker $USER && sg docker -c "cd ~/VCE-HQ && git pull && bash deploy.sh"'
