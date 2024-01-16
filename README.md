# Overview
This repository contains a Docker container setup for `nftables`, a powerful and simple host based firewall tool in Linux, equipped with an API for easy remote management. This solution is ideal for users looking to manage firewall rules efficiently in an environment that requires distribution agnostic tooling.

The Container must be ran with the `NET_ADMIN` capability and be in the host's network namespace.

# Usage
Replace the contents in the config.json file with your desired values and generate a TLS certificate named `cert.pem` and private key file named `cert.key` in the same directory as the dockerfile. Build the docker container and run it with the above mentioned configurations. 
