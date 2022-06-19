
host port: container port

    restart: always
    extra_hosts:
      - "host.docker.internal:host-gateway"

alias dpsa='sudo docker ps -a --format="table {{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}"'

    extra_hosts:
      - "host.docker.internal:172.17.0.1"