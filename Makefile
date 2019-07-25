CFLAGS = -Wall -W -O0 -g -ggdb -std=gnu11  -I$(shell pwd)/../external/libs/include -DREBRICK_DEBUG
LDFLAGS = -L$(shell pwd)/../external/libs/lib -luv -lssl -lcrypto

CFLAGSTEST = -std=c99 -Wall -W -O0 -g -ggdb -std=gnu11  -I$(shell pwd)/../src -I$(shell pwd)/../external/libs/include -DREBRICK_DEBUG2
LDFLAGSTEST = -L$(shell pwd)/../external/libs/lib -lcmocka -luv -lpthread -lssl -lcrypto




OUTPUT = rebrick
SRC = src
TEST = test
OBJS = main_rebrick.o rebrick_util.o rebrick_config.o rebrick_async_udpsocket.o rebrick_async_tcpsocket.o  \
 		rebrick_context.o rebrick_metrics.o rebrick_buffer.o ./lib/b64/decode.o ./lib/b64/encode.o  \

OBJSTEST = test.o ./server_client/udpecho.o ./server_client/tcpecho.o test_rebrick_util.o test_rebrick_config.o test_rebrick_context.o test_rebrick_metrics.o \
			test_rebrick_async_udpsocket.o test_rebrick_async_tcpsocket.o  test_rebrick_buffer.o \
			../src/rebrick_config.o ../src/rebrick_util.o  ../src/rebrick_context.o ../src/rebrick_metrics.o \
			../src/rebrick_async_udpsocket.o ../src/rebrick_async_tcpsocket.o ../src/rebrick_buffer.o\
			../src/lib/b64/encode.o ../src/lib/b64/decode.o




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
buildtest:
	@cd $(TEST) && make TEST=TRUE -f ../Makefile test

test : $(OBJSTEST)
	$(CC) -o test  $(OBJSTEST) $(LDFLAGSTEST)
testrun: test
	LD_LIBRARY_PATH=$(shell pwd)/../external/libs/lib LISTEN_PORT=9090 LISTEN_FAMILY=IPV4_IPV6  ./test



clean:
	find ./$(SRC) -name "*.o" -type f -delete
	find ./$(TEST) -name "*.o" -type f -delete
	rm -rf $(SRC)/rebrick
	rm -rf $(TEST)/test
	rm -rf output
	rm -rf out

