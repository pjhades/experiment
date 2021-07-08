CC = gcc
CFLAGS = -std=c11 -Wall -Werror -Wextra -g -D_GNU_SOURCE -fsanitize=undefined

ddd: src/*.c src/*.h
	$(CC) $(CFLAGS) -o $@ src/*.c

test/test_dns: test/test_dns.c
	$(CC) $(CFLAGS) -o $@ $^

UNITTESTS = test/test_dns
INTEGRATION = test/integration/test_query

test: $(UNITTESTS)
	$(foreach t,$(UNITTESTS),./$(t);)
	$(foreach t,$(INTEGRATION),./$(t);)

check: ddd
	valgrind --tool=memcheck \
             --trace-children=yes \
             --leak-check=full \
             --error-exitcode=1 \
             --error-exitcode=1 \
             ./ddd -p 9999
	dig @127.0.0.1 -p 9999 abc.com >/dev/null
	pkill memcheck

.PHONY: clean
clean:
	$(RM) $(UNITTESTS) ddd
