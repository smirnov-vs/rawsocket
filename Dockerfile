FROM alpine:latest AS builder

RUN apk add --update gcc g++ cmake make
COPY CMakeLists.txt main.cpp ./
RUN cmake -D CMAKE_BUILD_TYPE=Release -D CMAKE_CXX_FLAGS="-O2" . && make

FROM alpine:latest

RUN apk add --update iptables libstdc++ \
     && rm -rf /tmp/* /var/cache/apk/*

COPY --from=builder socket ./
COPY entrypoint.sh ./
ENTRYPOINT ["./entrypoint.sh"]
