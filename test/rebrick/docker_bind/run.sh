docker stop bind

docker run --rm -d \
  --name=bind \
  --publish 5555:53/udp \
  --publish 5555:53/tcp \
  internetsystemsconsortium/bind9:9.16
