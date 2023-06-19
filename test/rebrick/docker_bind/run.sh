docker stop bind || true

docker run --rm -d \
  --name=bind \
  --publish 5555:53/udp \
  --publish 5555:53/tcp \
  --volume $(pwd)/options.conf:/etc/bind/named.conf.options \
  internetsystemsconsortium/bind9:9.16
