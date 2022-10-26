docker stop bind
docker run --name bind --rm -d -ti --dns=127.0.0.1 \
  --publish 5555:53/udp --publish $IP:10000:10000 \
  --env='ROOT_PASSWORD=SecretPassword' \
  sameersbn/bind:latest
