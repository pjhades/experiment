#include "common.h"
#include "log.h"
#include "dns.h"
#include "net.h"
#include <getopt.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>

static void usage(void)
{
    errx(EXIT_SUCCESS,
         "ddd - DNS-daemon-demo\n"
         "Usage: ddd [Options]\n"
         "Options:\n"
         " -p, --port PORT  Listen on PORT instead of %s\n"
         "     --help       Print this message",
         DNS_PORT_STR);
}

static void daemonize(void)
{
    switch (fork()) {
        case -1: errx(EXIT_FAILURE, "first fork");
        case 0: break;
        default: exit(EXIT_SUCCESS);
    }
    if (setsid() == -1)
        err(EXIT_FAILURE, "setsid");
    switch (fork()) {
        case -1: err(EXIT_FAILURE, "second fork");
        case 0: break;
        default: exit(EXIT_SUCCESS);
    }

    int devnull = open("/dev/null", O_RDONLY);
    if (devnull == -1)
        err(EXIT_FAILURE, "open /dev/null");
    if (dup2(devnull, STDIN_FILENO) == -1)
        err(EXIT_FAILURE, "close stdin");
    if (dup2(devnull, STDOUT_FILENO) == -1)
        err(EXIT_FAILURE, "close stdout");
    if (dup2(devnull, STDERR_FILENO) == -1)
        err(EXIT_FAILURE, "close stderr");
    close(devnull);
}

int main(int argc, char **argv)
{
    struct option long_opts[] = {
        {"help", no_argument, NULL, 'H'},
        {"port", required_argument, NULL, 'p'},
        {0, 0, 0, 0},
    };
    struct config conf = {
        .port = DNS_PORT_STR,
    };
    int val;

    while ((val = getopt_long(argc, argv, "p:", long_opts, NULL)) != -1) {
        switch (val) {
            case 'H': usage(); break;
            case 'p': conf.port = optarg; break;
            case '?':
            default:
                errx(EXIT_FAILURE,
                     "Use --help to see a full list of options");
        }
    }

    log_init(argv[0]);
    udp_open(&conf);
    daemonize();
    net_loop(&conf);

    return 0;
}
