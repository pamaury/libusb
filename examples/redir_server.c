/*
* Redirection server that can talk to the libusb redir backend
* Copyright (c) 2023 Amaury Pouly <amaury.pouly@lowrisc.org>
*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public
* License as published by the Free Software Foundation; either
* version 2.1 of the License, or (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this library; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
*/

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <getopt.h>

#include "libusb.h"
#include "libusb_redir.h"

#define dbg(...) fprintf(stderr, "debug: "__VA_ARGS__)
#define err(...) fprintf(stderr, "error: "__VA_ARGS__)
#define warn(...) fprintf(stderr, "warn: "__VA_ARGS__)
#define info(...) fprintf(stderr, "info: "__VA_ARGS__)

#define CHECK_DBG(cond, err_code, msg, ...) \
    if(!(cond)) \
    { \
        dbg(msg, __VA_ARGS__); \
        return err_code; \
    }

struct device
{
    uint32_t device_id;
    libusb_device *dev; /* this keeps a reference to the device */
    /* number of times the devices has been opened */
    int open_count;
    /* we only keep one handle per device, which can be NULL if not opened */
    libusb_device_handle *handle;
    struct device *next;
};

uint32_t g_device_id_counter = 42;
struct device *g_dev_list_head;

static void fill_new_device(struct device *newdev, libusb_device *dev)
{
    newdev->device_id = g_device_id_counter++;
    newdev->dev = dev;
    newdev->open_count = 0;
    newdev->handle = NULL;
    info("new device dev_id=%lx, bus=%u, port=%u, addr=%u",
        (unsigned long)newdev->device_id, (unsigned)libusb_get_bus_number(dev),
        (unsigned)libusb_get_port_number(dev), (unsigned)libusb_get_device_address(dev));
}

/* return whether device exists or not */
static struct device *get_device_by_ptr_or_new(libusb_device *dev)
{
    struct device *cur = g_dev_list_head;
    while(cur)
    {
        if(cur->dev == dev)
            return cur;
        cur = cur->next;
    }
    /* could not find so allocate */
    struct device *newdev = malloc(sizeof(struct device));
    fill_new_device(newdev, dev);
    newdev->next = g_dev_list_head;
    g_dev_list_head = newdev;
    return newdev;
}

static struct device *get_device_by_id(uint32_t device_id)
{
    struct device *cur = g_dev_list_head;
    while(cur)
    {
        if(cur->device_id == device_id)
            return cur;
        cur = cur->next;
    }
    return NULL;
}

static int write_or_die(int socket, const void *buf, size_t size)
{
    const char *ptr = buf;
    while(size > 0)
    {
        int cnt = write(socket, ptr, size);
        if(cnt == 0)
            return LIBUSB_ERROR_IO; /* investigate if/when this can happen */
        if(cnt < 0)
            return cnt;
        size -= cnt;
        ptr += cnt;
    }
    return 0;
}

static int read_or_die(int socket, void *buf, size_t size)
{
    char *ptr = buf;
    while(size > 0)
    {
        dbg("wait read\n");
        int cnt = read(socket, ptr, size);
        if(cnt == 0)
            return LIBUSB_ERROR_IO; /* investigate if/when this can happen */
        if(cnt < 0)
            return cnt;
        size -= cnt;
        ptr += cnt;
    }
    return 0;
}

/* send packet, the pointer is to the payload, the header is handled by
 * this function; return 0 on success */
static int send_packet(int socket,
                       libusb_redir_packet_type_t type,
                       const void *packet, size_t length)
{
    dbg("sending packet type %lu, length %lu\n", (unsigned long)type, (unsigned long)length);
    libusb_redir_packet_header_t hdr;
    hdr.type = type;
    hdr.length = length; /* truncate, check length */
    int err = write_or_die(socket, &hdr, sizeof(hdr));
    if(err < 0)
        return err;
    /* handle empty payload */
    if(packet == 0 || length == 0)
        return 0;
    return write_or_die(socket, packet, length);
}

/* receive packet, allocate buffer */
static int recv_packet(int socket,
                       enum libusb_redir_packet_type *out_type,
                       void **packet, size_t *out_length)
{
    dbg("wait for packet\n");
    struct libusb_redir_packet_header hdr;

    int err = read_or_die(socket, &hdr, sizeof(hdr));
    if(err < 0)
        return err;
    dbg("  got packet type %lu length %lu\n", (unsigned long)hdr.type, (unsigned long)hdr.length);
    /* FIXME prevent attacker controlled allocation properly here */
    void *payload = malloc(hdr.length);
    if(payload == NULL)
        return LIBUSB_ERROR_NO_MEM;
    err = read_or_die(socket, payload, hdr.length);
    if(err < 0)
    {
        free(payload);
        return err;
    }
    dbg("  got packet data\n");
    *out_type = hdr.type;
    *packet = payload;
    *out_length = hdr.length;
    return LIBUSB_SUCCESS;
}

static int create_unix_socket(const char *name)
{
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if(sock == -1)
    {
        err("could not create unix socket: %s\n", strerror(errno));
        return -1;
    }
    struct sockaddr_un sockaddr;
    sockaddr.sun_family = AF_UNIX;
    if(strlen(name) + 1 > sizeof(sockaddr.sun_path))
    {
        err("unix socket name is too long\n");
        close(sock);
        return -1;
    }
    strcpy(sockaddr.sun_path, name);
    /* if the first character of name is @, create an abstract socket */
    if(name[0] == '@')
        sockaddr.sun_path[0] = 0; /* creates an abstract socket */
    int err = bind(sock, (struct sockaddr*)&sockaddr, sizeof(sockaddr.sun_family) + strlen(name));
    if(err != 0)
    {
        err("could not bind socket: %d\n", err);
        close(sock);
        return -1;
    }
    return sock;
}

static int do_hello(int socket, libusb_redir_hello_packet_t *in_hello)
{
    /* if the magic and protocol values don't match, don't bothering answering */
    CHECK_DBG(in_hello->magic == LIBUSB_REDIR_HELLO_MAGIC, LIBUSB_ERROR_NOT_SUPPORTED,
        "magic value is wrong (%llx), expected %llx", (unsigned long long)in_hello->magic,
        (unsigned long long)LIBUSB_REDIR_HELLO_MAGIC);
    CHECK_DBG(in_hello->protocol_version == LIBUSB_REDIR_V1, LIBUSB_ERROR_NOT_SUPPORTED,
        "protocol value is wrong (%x), expected %x", in_hello->protocol_version,
        LIBUSB_REDIR_V1);
    dbg("received hello, impl_version = %.64s\n", in_hello->impl_version);
    /* send back */
    libusb_redir_hello_packet_t hello =
    {
        .magic = LIBUSB_REDIR_HELLO_MAGIC,
        .protocol_version = LIBUSB_REDIR_V1,
        .impl_version = {0},
    };
    snprintf(hello.impl_version, sizeof(hello.impl_version),
             "redir_server 0.1");
    return send_packet(socket, LIBUSB_REDIR_HELLO, &hello, sizeof(hello));
}

static void serve_client(int sock)
{
    bool stop = false;
    while(!stop)
    {
        libusb_redir_packet_type_t type;
        void *payload = NULL;
        size_t length;
        int err = recv_packet(sock, &type, &payload, &length);
        if(err < 0)
            break;
        #define DO_PAYLOAD_SIZE_EXACT(pkt_type_str, type, fn) \
            do { \
                if(length != sizeof(type)) { \
                    dbg("%s packet has wrong payload size %lu (expected %lu), ignore\n", \
                        pkt_type_str, (unsigned long)length, (unsigned long)sizeof(type)); \
                } \
                else { \
                    err = fn(sock, payload); \
                    if(err < 0) { \
                        dbg("fatal error when handling %s packet: err=%d", pkt_type_str, err); \
                        stop = true; \
                    } \
                } \
                free(payload); \
            } while(0)

        switch(type)
        {
            case LIBUSB_REDIR_HELLO:
                DO_PAYLOAD_SIZE_EXACT("hello", libusb_redir_hello_packet_t, do_hello);
                break;
            default:
                /* ignore */
                dbg("ignore request %lu\n", (unsigned long)type);
                break;
        }
    }
    printf("closing connection with client\n");
    close(sock);
}

static const struct option longopts[] =
{
    { "port", required_argument, NULL, 'p' },
    { "unix", required_argument, NULL, 'u' },
    { "verbose", no_argument, NULL, 'v' },
    { "help", no_argument, NULL, 'h' },
    { NULL, 0, NULL, 0 }
};

static void usage(const char *progname)
{
    printf("usage: %s [options]\n", progname);
    printf("options:\n");
    printf(" -v, --verbose      increase verbosity level");
    printf(" -h, --help         print help and quit");
    printf(" -p, --port PORT    listen for clients on port PORT (use 0 to use any available port)");
    printf(" -u, --unix NAME    listen for clients on the unix socket named NAME");
    exit(1);
}

int main(int argc, char **argv)
{
    int port = -1;
    int verbose = 0;
    const char *unix_name = NULL;
    while(true)
    {
        int o = getopt_long(argc, argv, "hp:vu:", longopts, NULL);
        if(o == -1)
            break;
        switch (o)
        {
            case 'p':
            {
                char *endptr;
                port = strtol(optarg, &endptr, 10);
                if(*endptr != '\0')
                {
                    fprintf(stderr, "error: invalid port '%s'\n", optarg);
                    return 1;
                }
                break;
            }
            case 'u':
                unix_name = optarg;
                break;
            case 'v':
                verbose++;
                break;
            case 'h':
                usage(argv[0]);
                break;
            default:
                // getopt already prints an error message
                return 1;
        }
    }
    if(optind != argc)
    {
        fprintf(stderr, "error: extra arguments on the command line starting at '%s'\n", argv[optind]);
        return 1;
    }
    if(unix_name && port != -1)
    {
        fprintf(stderr, "you can specify either a port or a unix socket name but not both\n");
        return 1;
    }
    /* create socket */
    int socket = -1;
    if(unix_name)
        socket = create_unix_socket(unix_name);
    else if(port != -1)
    {
        fprintf(stderr, "creating a socket with a port is not implemented yet\n");
        return 1;
    }
    else
    {
        fprintf(stderr, "you need to specify either a port or a unix socket name\n");
        return 1;
    }
    if(socket == -1)
        return 1;
    /* start libusb */
    libusb_init(NULL);
    /* start */
    info("waiting for connections...\n");
    int err = listen(socket, 1);
    if(err != 0)
    {
        err("error: cannot listen on socket: %d", err);
        close(socket);
        return 1;
    }
    while(true)
    {
        struct sockaddr_un remote;
        socklen_t sock_len = sizeof(remote);
        int client_sock = accept(socket, (struct sockaddr *)&remote, &sock_len);
        if(client_sock == -1)
        {
            err("could not accept client\n");
            break;
        }
        info("client connected\n");
        serve_client(client_sock);
    }
    close(socket);
    return 0;
}
