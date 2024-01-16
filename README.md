# Overview
This repository contains a Docker container setup for `nftables`, a powerful simple firewall tool in Linux, equipped with an API for easy remote management. This solution is ideal for users looking to manage firewall rules efficiently in a containerized environment that is Distribution agnostic.

The Container must be ran with the `NET_ADMIN` capability and be in the host's network namespace.

# Usage
Replace the contents in the config.json file with your desired values and generate a TLS certificate named `cert.pem` and private key file named `cert.key` in the same directory as the dockerfile. From there, build the docker container and run it with the above mentioned configurations. 
