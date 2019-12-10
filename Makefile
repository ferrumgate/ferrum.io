CFLAGS = -fPIC -Wall -W -O0 -g -ggdb -std=gnu11  -I$(shell pwd)/../external/libs/include -DREBRICK_DEBUG
LDFLAGS = -shared  -o librebrick.so.1.0.0 -L$(shell pwd)/../external/libs/lib -luv -lssl -lcrypto -lnghttp2

CFLAGSTEST =  -Wall -Wno-unused-function -W -O0 -g -ggdb -std=gnu11  -I$(shell pwd)/../src -I$(shell pwd)/../external/libs/include -DREBRICK_DEBUG2
LDFLAGSTEST = -L$(shell pwd)/../external/libs/lib -lcmocka -luv -lpthread -lssl -lcrypto -lnghttp2




OUTPUT = rebrick
SRC = src
TEST = test
OBJS = ./common/rebrick_util.o ./common/rebrick_resolve.o ./common/rebrick_timer.o ./socket/rebrick_udpsocket.o ./socket/rebrick_tcpsocket.o ./common/rebrick_tls.o \
		 ./socket/rebrick_tlssocket.o ./http/rebrick_http.o ./http/rebrick_httpsocket.o \
		 ./http/rebrick_http2socket.o ./http/rebrick_websocket.o \
 		 ./common/rebrick_buffers.o ./common/rebrick_buffer.o ./lib/b64/decode.o ./lib/b64/encode.o ./lib/picohttpparser.o   \

OBJSTEST = test.o ./server_client/udpecho.o ./server_client/tcpecho.o test_rebrick_util.o test_rebrick_resolve.o \
			 test_rebrick_tls.o test_rebrick_timer.o \
			test_rebrick_udpsocket.o test_rebrick_tcpsocket.o test_rebrick_tlssocket.o test_rebrick_http.o test_rebrick_httpsocket.o \
			test_rebrick_http2socket.o test_rebrick_buffer.o test_rebrick_buffers.o \
			../src/common/rebrick_util.o  ../src/common/rebrick_resolve.o ../src/common/rebrick_timer.o  \
			../src/socket/rebrick_udpsocket.o ../src/socket/rebrick_tcpsocket.o ../src/common/rebrick_buffer.o ../src/common/rebrick_buffers.o\
			../src/lib/b64/encode.o ../src/lib/b64/decode.o ../src/lib/picohttpparser.o \
			../src/common/rebrick_tls.o ../src/socket/rebrick_tlssocket.o ../src/http/rebrick_http.o ../src/http/rebrick_httpsocket.o  \
			../src/http/rebrick_http2socket.o  ../src/http/rebrick_websocket.o




ifeq ($(TEST),TRUE)
%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGSTEST)
else
%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

endif

all:clean
	@cd $(SRC) && make -f ../Makefile $(OUTPUT)

rebrick : $(OBJS)
	$(CC)  $(OBJS) $(LDFLAGS)
	ar -r -o librebrick.a $(OBJS)


check:clean
	@cd $(TEST) && make TEST=TRUE -f ../Makefile testrun
checkvalgrind:clean
	@cd $(TEST) && make TEST=TRUE -f ../Makefile testrunvalgrind
buildtest:
	@cd $(TEST) && make TEST=TRUE -f ../Makefile test

test : $(OBJSTEST)
	$(CC) -o test  $(OBJSTEST) $(LDFLAGSTEST)
testrun: test
	LD_LIBRARY_PATH=$(shell pwd)/../external/libs/lib LISTEN_PORT=9090 LISTEN_FAMILY=IPV4_IPV6 SSLKEYLOGFILE=/home/hframe/ssl-key.log  ./test
testrunvalgrind: test
	LD_LIBRARY_PATH=$(shell pwd)/../external/libs/lib LISTEN_PORT=9090 LISTEN_FAMILY=IPV4_IPV6 valgrind -v --track-origins=yes --leak-check=full --show-leak-kinds=all   --gen-suppressions=all --suppressions=$(shell pwd)/valgrind.options  ./test



clean:
	find ./$(SRC) -name "*.o" -type f -delete
	find ./$(TEST) -name "*.o" -type f -delete
	rm -rf $(SRC)/librebrick.a
	rm -rf $(SRC)/librebrick.so*
	rm -rf $(TEST)/test
	rm -rf output
	rm -rf out

