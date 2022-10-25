CFLAGS = -fPIC -Wall -W -O0 -g -ggdb -std=gnu11  -I$(shell pwd)/../external/libs/include -DREBRICK_DEBUG
LDFLAGS = -shared  -o librebrick.so.1.0.0 -L$(shell pwd)/../external/libs/lib -luv -lssl -lcrypto -lnghttp2

CFLAGSTEST =  -Wall -Wno-unused-function -W -O0 -g -ggdb -std=gnu11  -I$(shell pwd)/../src -I$(shell pwd)/../external/libs/include -DREBRICK_DEBUG2
LDFLAGSTEST = -L$(shell pwd)/../external/libs/lib -lcmocka -luv -lpthread -lssl -lcrypto -lnghttp2




OUTPUT = rebrick
SRC = src
TEST = test
OBJS = ./rebrick/common/rebrick_util.o ./rebrick/common/rebrick_log.o ./rebrick/common/rebrick_resolve.o ./rebrick/common/rebrick_timer.o ./rebrick/socket/rebrick_udpsocket.o ./rebrick/socket/rebrick_tcpsocket.o \
	./rebrick/common/rebrick_tls.o \
		 ./rebrick/socket/rebrick_tlssocket.o ./rebrick/http/rebrick_http.o ./rebrick/http/rebrick_httpsocket.o \
		 ./rebrick/http/rebrick_http2socket.o ./rebrick/http/rebrick_websocket.o \
 		 ./rebrick/common/rebrick_buffers.o ./rebrick/common/rebrick_buffer.o ./rebrick/lib/b64/decode.o \
		 ./rebrick/lib/b64/encode.o ./rebrick/lib/picohttpparser.o   \
		  ./rebrick/file/rebrick_filestream.o

OBJSTEST = test.o ./rebrick/server_client/udpecho.o ./rebrick/server_client/tcpecho.o ./rebrick/test_rebrick_util.o ./rebrick/test_rebrick_resolve.o \
			 ./rebrick/test_rebrick_tls.o ./rebrick/test_rebrick_timer.o \
			./rebrick/test_rebrick_udpsocket.o ./rebrick/test_rebrick_tcpsocket.o ./rebrick/test_rebrick_tlssocket.o ./rebrick/test_rebrick_http.o ./rebrick/test_rebrick_httpsocket.o \
			./rebrick/test_rebrick_http2socket.o ./rebrick/test_rebrick_buffer.o ./rebrick/test_rebrick_buffers.o \
			./rebrick/test_rebrick_filestream.o \
			../src/rebrick/common/rebrick_util.o ../src/rebrick/common/rebrick_log.o  ../src/rebrick/common/rebrick_resolve.o ../src/rebrick/common/rebrick_timer.o  \
			../src/rebrick/socket/rebrick_udpsocket.o ../src/rebrick/socket/rebrick_tcpsocket.o ../src/rebrick/common/rebrick_buffer.o ../src/rebrick/common/rebrick_buffers.o\
			../src/rebrick/lib/b64/encode.o ../src/rebrick/lib/b64/decode.o ../src/rebrick/lib/picohttpparser.o \
			../src/rebrick/common/rebrick_tls.o ../src/rebrick/socket/rebrick_tlssocket.o ../src/rebrick/http/rebrick_http.o ../src/rebrick/http/rebrick_httpsocket.o  \
			../src/rebrick/http/rebrick_http2socket.o  ../src/rebrick/http/rebrick_websocket.o \
			../src/rebrick/file/rebrick_filestream.o




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
	LD_LIBRARY_PATH=$(shell pwd)/../external/libs/lib LISTEN_PORT=9090 LISTEN_FAMILY=IPV4_IPV6 SSLKEYLOGFILE=/home/hframed/ssl-key.log  ./test
testrunvalgrind: test
	LD_LIBRARY_PATH=$(shell pwd)/../external/libs/lib LISTEN_PORT=9090 LISTEN_FAMILY=IPV4_IPV6 valgrind -v --track-origins=yes --leak-check=full --show-leak-kinds=all   --gen-suppressions=all --suppressions=$(shell pwd)/valgrind.options  ./test



clean:
	find ./$(SRC) -name "*.o" -type f -delete
	find ./$(TEST) -name "*.o" -type f -delete -not -path ./$(TEST)/docker_bind
	rm -rf $(SRC)/librebrick.a
	rm -rf $(SRC)/librebrick.so*
	rm -rf $(TEST)/test
	rm -rf output
	rm -rf out

