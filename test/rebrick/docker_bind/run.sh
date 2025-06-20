docker stop bind || true
docker run --rm -d \
  --name=bind \
  --publish 5555:53/udp \
  --publish 5555:53/tcp \
  --publish "$1":5554:53/udp \
  --volume "$(pwd)"/options.conf:/etc/bind/named.conf \
  internetsystemsconsortium/bind9:9.20
