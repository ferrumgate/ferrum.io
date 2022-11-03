###  part 1 #######################
FROM debian:11-slim as builder

RUN locale
RUN apt update &&\
    apt install --assume-yes --no-install-recommends build-essential \
    automake autoconf libtool cmake zlib1g-dev libpam0g-dev unzip libnetfilter-conntrack-dev conntrack

#Create app directory
RUN mkdir /cores
WORKDIR /ferrum.io
COPY . .

WORKDIR /ferrum.io/external
RUN ["chmod", "+x", "prepare.libs.sh"]
RUN ./prepare.libs.sh
WORKDIR /ferrum.io
RUN make clean && make

#FROM hamza:latest as builder

FROM debian:11-slim
RUN locale
RUN apt update && \ 
    apt install --assume-yes --no-install-recommends zlib1g iproute2 conntrack

WORKDIR /ferrum.io
COPY --from=builder /ferrum.io/src /ferrum.io/src
COPY --from=builder /ferrum.io/external/libs/lib /ferrum.io/external/libs/lib
COPY --from=builder /ferrum.io/external/libs/bin /ferrum.io/external/libs/bin
COPY ferrum.io.sh /ferrum.io/
RUN chmod +x /ferrum.io/ferrum.io.sh
RUN ls /ferrum.io/external/libs/lib
CMD [ "/ferrum.io/ferrum.io.sh" ]









