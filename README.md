# About

ferrum.io is an open source network proxy library(tcp,udp,ssl,http,https,grpc support), for implementing services in ferrumgate zero trust framework

## Prerequities
under external folder, there are some libs like libuv for async I/O,
and for unit testing cmock project,
run makeready.sh script, for preparing compile environment

## Compile


``` compile
make check
make
```
## Run
Preparing!!!!!

## Troubleshot
if cannot find any so library
export LD_LIBRARY_PATH=$(pwd)/../external/libs/lib

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)
