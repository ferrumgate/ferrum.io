CFLAGS = -Wall -W -O0 -g -ggdb -std=gnu11  -I$(shell pwd)/../external/libs/include -DREBRICK_DEBUG
LDFLAGS = -L$(shell pwd)/../external/libs/lib -luv -lssl -lcrypto

CFLAGSTEST = -std=c99 -Wall -Wno-unused-function -W -O0 -g -ggdb -std=gnu11  -I$(shell pwd)/../src -I$(shell pwd)/../external/libs/include -DREBRICK_DEBUG2
LDFLAGSTEST = -L$(shell pwd)/../external/libs/lib -lcmocka -luv -lpthread -lssl -lcrypto




OUTPUT = rebrick
SRC = src
TEST = test
OBJS = main_rebrick.o ./common/rebrick_util.o ./common/rebrick_config.o ./socket/rebrick_udpsocket.o ./socket/rebrick_tcpsocket.o ./common/rebrick_tls.o \
		 ./socket/rebrick_tlssocket.o ./http/rebrick_httpsocket.o \
 		./common/rebrick_context.o ./common/rebrick_metrics.o ./common/rebrick_buffers.o ./common/rebrick_buffer.o ./lib/b64/decode.o ./lib/b64/encode.o ./lib/picohttpparser.o   \

OBJSTEST = test.o ./server_client/udpecho.o ./server_client/tcpecho.o test_rebrick_util.o \
			 test_rebrick_config.o test_rebrick_context.o test_rebrick_metrics.o \
			 test_rebrick_tls.o \
			test_rebrick_udpsocket.o test_rebrick_tcpsocket.o test_rebrick_tlssocket.o test_rebrick_httpsocket.o test_rebrick_buffer.o test_rebrick_buffers.o \
			../src/common/rebrick_config.o ../src/common/rebrick_util.o  ../src/common/rebrick_context.o ../src/common/rebrick_metrics.o \
			../src/socket/rebrick_udpsocket.o ../src/socket/rebrick_tcpsocket.o ../src/common/rebrick_buffer.o ../src/common/rebrick_buffers.o\
			../src/lib/b64/encode.o ../src/lib/b64/decode.o ../src/lib/picohttpparser.o \
			../src/common/rebrick_tls.o ../src/socket/rebrick_tlssocket.o ../src/http/rebrick_httpsocket.o




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
	$(CC) -o $(OUTPUT) $(OBJS) $(LDFLAGS)


check:clean
	@cd $(TEST) && make TEST=TRUE -f ../Makefile testrun
checkvalgrind:clean
	@cd $(TEST) && make TEST=TRUE -f ../Makefile testrunvalgrind
buildtest:
	@cd $(TEST) && make TEST=TRUE -f ../Makefile test

test : $(OBJSTEST)
	$(CC) -o test  $(OBJSTEST) $(LDFLAGSTEST)
testrun: test
	LD_LIBRARY_PATH=$(shell pwd)/../external/libs/lib  LISTEN_PORT=9090 LISTEN_FAMILY=IPV4_IPV6  ./test
testrunvalgrind: test
	LD_LIBRARY_PATH=$(shell pwd)/../external/libs/lib LISTEN_PORT=9090 LISTEN_FAMILY=IPV4_IPV6 valgrind -v --track-origins=yes --leak-check=full --show-leak-kinds=all   --gen-suppressions=all --suppressions=$(shell pwd)/valgrind.options  ./test



clean:
	find ./$(SRC) -name "*.o" -type f -delete
	find ./$(TEST) -name "*.o" -type f -delete
	rm -rf $(SRC)/rebrick
	rm -rf $(TEST)/test
	rm -rf output
	rm -rf out

