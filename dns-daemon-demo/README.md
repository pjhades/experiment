# DNS daemon demo

## How to build and run
- To build it, run `make`.
- To build and run tests, run `make && make test`.
- To start the daemon on UDP port 53, run `./ddd`. This requires super user privilege.
- To start the daemon on an arbitrary port `<PORT>`, run `./ddd -p <PORT>`.
- To run valgrind against the executable, run `make check`.

## How to view the logs
Simple logs are written to syslog,
which is usually captured by systemd nowadays,
so it can be found with
```
journalctl | grep ddd
```

## About the daemon
The functionality of the daemon is very restricted.
It only accepts DNS queries that 
- have exactly one question, and
- have query type A, and
- have query class IN

All other queries will be dropped.
