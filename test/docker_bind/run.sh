#mkdir -p $(pwd)/bind_data
#sudo chmod 777 -R $(pwd)/bind_data
docker run  --dns=127.0.0.1 \
  --publish 5555:53/udp --publish $IP:10000:10000 \
--env='ROOT_PASSWORD=SecretPassword' \
sameersbn/bind:latest
