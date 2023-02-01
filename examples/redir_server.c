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
                       enum libusb_redir_packet_type type,
                       const void *packet, size_t length)
{
    dbg("sending packet type %lu, length %lu\n", (unsigned long)type, (unsigned long)length);
    struct libusb_redir_packet_header hdr;
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
static int wait_packet(int socket,
                       enum libusb_redir_packet_type *out_type,
                       void **packet, size_t *out_length)
{
    dbg("wait for packet type\n");
    struct libusb_redir_packet_header hdr;

    int err = read_or_die(socket, &hdr, sizeof(hdr));
    if(err < 0)
        return err;
    dbg("  got packet type %lu length %lu\n", (unsigned long)hdr.type, (unsigned long)hdr.length);
    /* FIXME prevent attacker controlled allocation here */
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

static int send_device_list(int sock)
{
    ssize_t cnt;
    libusb_device **devs;
    cnt = libusb_get_device_list(NULL, &devs);
    if(cnt < 0)
        return cnt; /* maybe send empty list? */
    /* allocate buffer */
    size_t dev_list_size = sizeof(struct libusb_redir_packet_dev_list);
    dev_list_size += cnt * sizeof(struct libusb_redir_packet_dev_list_entry);
    struct libusb_redir_packet_dev_list *dev_list = malloc(dev_list_size);
    /* fill list */
    dev_list->nr_devices = cnt;
    for(int i = 0; i < cnt; i++)
    {
        dev_list->device[i].bus_number = libusb_get_bus_number(devs[i]);
        dev_list->device[i].port_number = libusb_get_port_number(devs[i]);
        dev_list->device[i].device_address = libusb_get_device_address(devs[i]);
        /* also update global list at the same time */
        struct device *dev = get_device_by_ptr_or_new(devs[i]);
        dev_list->device[i].device_id = dev->device_id;
    }
    libusb_free_device_list(devs, 0); /* don't unref, references are held by the global list */
    /* send it */
    int err = send_packet(sock, LIBUSB_REDIR_DEVICE_LIST, dev_list, dev_list_size);
    free(dev_list);
    return err;
}

static void fill_dev_desc(struct usbi_device_descriptor *desc_out, struct libusb_device_descriptor *desc_in)
{
    /* TODO: delocalize value LE/BE */
    desc_out->bLength = desc_in->bLength;
    desc_out->bDescriptorType = desc_in->bDescriptorType;
    desc_out->bcdUSB = desc_in->bcdUSB;
    desc_out->bDeviceClass = desc_in->bDeviceClass;
    desc_out->bDeviceSubClass = desc_in->bDeviceSubClass;
    desc_out->bDeviceProtocol = desc_in->bDeviceProtocol;
    desc_out->bMaxPacketSize0 = desc_in->bMaxPacketSize0;
    desc_out->idVendor = desc_in->idVendor;
    desc_out->idProduct = desc_in->idProduct;
    desc_out->bcdDevice = desc_in->bcdDevice;
    desc_out->iManufacturer = desc_in->iManufacturer;
    desc_out->iProduct = desc_in->iProduct;
    desc_out->iProduct = desc_in->iProduct;
    desc_out->iSerialNumber = desc_in->iSerialNumber;
    desc_out->bNumConfigurations = desc_in->bNumConfigurations;
}

static int send_device_descriptor(int sock, struct libusb_redir_packet_get_dev_desc *req)
{
    dbg("got request for device descriptor for device id %lx\n", (unsigned long)req->device_id);
    struct device *dev = get_device_by_id(req->device_id);
    if(dev == NULL)
    {
        err("device id %lx does not exist\n", (unsigned long)req->device_id);
        return LIBUSB_ERROR_NO_DEVICE;
    }
    struct libusb_redir_packet_dev_desc dev_desc;
    dev_desc.device_id = req->device_id;
    /* we need a copy of the descriptor to avoid unaligned stuff because of the packed structure */
    struct libusb_device_descriptor desc;
    int err = libusb_get_device_descriptor(dev->dev, &desc);
    if(err != LIBUSB_SUCCESS)
    {
        err("cannot get device descriptor for device id %lx\n", (unsigned long)req->device_id);
        return err;
    }
    fill_dev_desc(&dev_desc.desc, &desc);
    /* send it */
    return send_packet(sock, LIBUSB_REDIR_DEVICE_DESCRIPTOR, &dev_desc, sizeof(dev_desc));
}

static int send_config_descriptor(int sock, struct libusb_redir_packet_get_config_desc *req)
{
    dbg("got request for config descriptor %x for device id %lx\n",
        (unsigned)req->config_index, (unsigned long)req->device_id);
    struct device *dev = get_device_by_id(req->device_id);
    if(dev == NULL)
    {
        err("device id %lx does not exist\n", (unsigned long)req->device_id);
        return LIBUSB_ERROR_NO_DEVICE;
    }
    /* we don't want to really use libusb_get_config_descriptor because it doesn't give the raw
     * descriptor, but the parsed one
     * here I use it to first get the total length and then do an actual request, this requires
     * to open the device which is not great */
    struct libusb_config_descriptor *desc;
    int err = libusb_get_config_descriptor(dev->dev, req->config_index, &desc);
    if(err != LIBUSB_SUCCESS)
    {
        err("cannot for config descriptor %x for device id %lx\n",
            (unsigned)req->config_index, (unsigned long)req->device_id);
        return err;
    }
    int desc_tot_len = desc->wTotalLength;
    libusb_free_config_descriptor(desc);
    /* allocate */
    size_t tot_size = sizeof(struct libusb_redir_packet_config_desc) + desc_tot_len;
    struct libusb_redir_packet_config_desc *config_desc = malloc(tot_size);
    config_desc->device_id = req->device_id;
    /* retrieve it */
    libusb_device_handle *handle;
    err = libusb_open(dev->dev, &handle);
    if(err < 0)
    {
        free(config_desc);
        err("cannot open device\n");
        return err;
    }
    err = libusb_get_descriptor(handle, LIBUSB_DT_CONFIG, req->config_index, (void *)config_desc->desc, desc_tot_len);
    if(err < 0)
    {
        free(config_desc);
        err("cannot open device\n");
        return err;
    }
    libusb_close(handle);
    /* send it */
    err = send_packet(sock, LIBUSB_REDIR_CONFIG_DESCRIPTOR, config_desc, tot_size);
    free(config_desc);
    return err;
}

static int do_open_close(int sock, struct libusb_redir_packet_open_close *req, bool open)
{
    dbg("got request for open/close for device id %lx\n", (unsigned long)req->device_id);
    struct device *dev = get_device_by_id(req->device_id);
    if(dev == NULL)
    {
        err("device id %lx does not exist\n", (unsigned long)req->device_id);
        return LIBUSB_ERROR_NO_DEVICE;
    }
    /* open */
    if(open)
    {
        struct libusb_redir_packet_open_status status;
        if(dev->open_count++ == 0)
        {
            int err = libusb_open(dev->dev, &dev->handle);
            if(err < 0)
            {
                status.status = -err;
                err("cannot open device");
            }
            else
                status.status = LIBUSB_SUCCESS;
        }
        else
            status.status = LIBUSB_SUCCESS;
        /* send status */
        status.device_id = dev->device_id;
        return send_packet(sock, LIBUSB_REDIR_OPEN_STATUS, &status, sizeof(status));
    }
    /* close */
    else
    {
        if(dev->open_count == 0)
            warn("ignoring close, the device was not open");
        else if(--dev->open_count == 0)
        {
            libusb_close(dev->handle);
            dev->handle = NULL;
        }
        return LIBUSB_SUCCESS;
    }
}

/* ugly, will get rid of that when we do proper async i/o */
static void LIBUSB_CALL redir_sync_transfer_cb(struct libusb_transfer *transfer)
{
    int *completed = transfer->user_data;
    *completed = 1;
    dbg("transfer completed with status %d, actual_length=%d\n",
            transfer->status, transfer->actual_length);
    /* caller interprets result and frees transfer */
}

static void redir_sync_transfer_wait_for_completion(struct libusb_transfer *transfer)
{
    int *completed = transfer->user_data;
    struct libusb_context *ctx = HANDLE_CTX(transfer->dev_handle);

    while(!*completed)
    {
        int r = libusb_handle_events_completed(ctx, completed);
        if(r < 0)
        {
            if(r == LIBUSB_ERROR_INTERRUPTED)
                continue;
            err("libusb_handle_events failed: %s, cancelling transfer and retrying",
                    libusb_error_name(r));
            libusb_cancel_transfer(transfer);
            continue;
        }
        if(NULL == transfer->dev_handle)
        {
            /* transfer completion after libusb_close() */
            transfer->status = LIBUSB_TRANSFER_NO_DEVICE;
            *completed = 1;
        }
    }
}

static int send_transfer_status_error(int sock, struct libusb_redir_packet_submit_transfer *xfer, enum libusb_transfer_status status)
{
    /* send back error */
    struct libusb_redir_packet_transfer_status status_err;
    status_err.device_id = xfer->device_id;
    status_err.transfer_id = xfer->transfer_id;
    status_err.status = status;
    status_err.length = 0;
    dbg("send transfer status dev_id=%d, xfer_id=%d, status=%lu (error)\n", status_err.device_id, status_err.transfer_id,
        status_err.status);
    dbg("len=%lu\n", sizeof(status_err));
    return send_packet(sock, LIBUSB_REDIR_TRANSFER_STATUS, &status_err, sizeof(status_err));
}

/* frees transfer->buffer and transfer */
static int send_transfer_status_ok(int sock, struct libusb_redir_packet_submit_transfer *xfer,
                                   struct libusb_transfer *transfer)
{
    /* send back error */
    size_t tot_sz = sizeof(struct libusb_redir_packet_transfer_status) + transfer->actual_length;
    struct libusb_redir_packet_transfer_status *status = malloc(tot_sz);
    status->device_id = xfer->device_id;
    status->transfer_id = xfer->transfer_id;
    status->status = LIBUSB_TRANSFER_COMPLETED;
    status->length = transfer->actual_length;
    memcpy(status + 1, transfer->buffer, transfer->actual_length);
    free(transfer->buffer);
    libusb_free_transfer(transfer);
    dbg("send transfer status dev_id=%d, xfer_id=%d, status=%lu length=%lu\n", status->device_id, status->transfer_id,
        status->status, (unsigned long)status->length);
    int err = send_packet(sock, LIBUSB_REDIR_TRANSFER_STATUS, status, tot_sz);
    free(status);
    return err;
}

static int submit_transfer(int sock, struct libusb_redir_packet_submit_transfer *xfer, size_t xfer_tot_len)
{
    dbg("transfer submitted: device_id=%d, xfer_id=%d, endpoint=%x, length=%lu\n",
        xfer->device_id, xfer->transfer_id, xfer->endpoint, (unsigned long)xfer->length);
    /* find device */
    struct device *dev = get_device_by_id(xfer->device_id);
    if(dev == NULL)
    {
        err("device id %lx does not exist\n", (unsigned long)xfer->device_id);
        return send_transfer_status_error(sock, xfer, LIBUSB_TRANSFER_NO_DEVICE);
    }
    if(dev->open_count == 0)
    {
        err("device id %lx has not been opened\n", (unsigned long)xfer->device_id);
        return send_transfer_status_error(sock, xfer, LIBUSB_TRANSFER_NO_DEVICE);
    }

    bool is_in = !!(xfer->endpoint & LIBUSB_ENDPOINT_IN);
    /* check length */
    size_t expected_tot_len = sizeof(struct libusb_redir_packet_submit_transfer);
    if(!is_in)
        expected_tot_len += xfer->length;
    else if(xfer->type == LIBUSB_TRANSFER_TYPE_CONTROL)
        expected_tot_len += LIBUSB_CONTROL_SETUP_SIZE;
    if(xfer_tot_len != expected_tot_len)
    {
        dbg("transfer packet has the wrong total size\n");
        return send_transfer_status_error(sock, xfer, LIBUSB_TRANSFER_ERROR);
    }
    /* build request */
    struct libusb_transfer *transfer = libusb_alloc_transfer(0);
    if(transfer == NULL)
        return send_transfer_status_error(sock, xfer, LIBUSB_TRANSFER_ERROR);
    transfer->dev_handle = dev->handle;
    transfer->timeout = xfer->timeout;
    transfer->endpoint = xfer->endpoint;
    transfer->type = xfer->type;
    transfer->length = xfer->length;
    transfer->buffer = malloc(transfer->length);
    if(!is_in)
        memcpy(transfer->buffer, xfer + 1, transfer->length);
    else if(transfer->type == LIBUSB_TRANSFER_TYPE_CONTROL)
        memcpy(transfer->buffer, xfer + 1, LIBUSB_CONTROL_SETUP_SIZE);
    /* we use a variable to notify completion */
    int completed = 0;
    transfer->user_data = &completed;
    transfer->callback = &redir_sync_transfer_cb;
    int err = libusb_submit_transfer(transfer);
    if(err < 0)
    {
        free(transfer->buffer);
        dbg("transfer submission failed\n");
        return send_transfer_status_error(sock, xfer, LIBUSB_TRANSFER_ERROR);
    }
    /* wait for completion */
    dbg("transfer submitted, waiting for completion\n");
    /* see https://libusb.sourceforge.io/api-1.0/libusb_mtasync.html on the
     * proper way of doing this, code stolen from the sync.c file */
    redir_sync_transfer_wait_for_completion(transfer);
    if(transfer->status == LIBUSB_TRANSFER_COMPLETED)
        return send_transfer_status_ok(sock, xfer, transfer); /* will free the buffer */
    else
    {
        enum libusb_transfer_status status = transfer->status;
        libusb_free_transfer(transfer);
        free(transfer->buffer);
        return send_transfer_status_error(sock, xfer, status);
    }
}

static void serve_client(int sock)
{
    while(true)
    {
        enum libusb_redir_packet_type type;
        void *payload = NULL;
        size_t length;
        int err = wait_packet(sock, &type, &payload, &length);
        if(err < 0)
            break;
        switch(type)
        {
            case LIBUSB_REDIR_REQUEST_DEVICE_LIST:
                if(length > 0)
                {
                    dbg("dev list request has some payload, strange\n");
                    free(payload);
                }
                send_device_list(sock); /* ignore error? */
                break;
            case LIBUSB_REDIR_REQUEST_DEVICE_DESCRIPTOR:
                if(length != sizeof(struct libusb_redir_packet_get_dev_desc))
                {
                    dbg("dev desc request has wrong payload size, ignore\n");
                    free(payload);
                }
                send_device_descriptor(sock, payload);
                free(payload);
                break;
            case LIBUSB_REDIR_REQUEST_CONFIG_DESCRIPTOR:
                if(length != sizeof(struct libusb_redir_packet_get_config_desc))
                {
                    dbg("config desc request has wrong payload size, ignore\n");
                    free(payload);
                }
                send_config_descriptor(sock, payload);
                free(payload);
                break;
            case LIBUSB_REDIR_OPEN_DEVICE:
            case LIBUSB_REDIR_CLOSE_DEVICE:
                if(length != sizeof(struct libusb_redir_packet_open_close))
                {
                    dbg("open/close request has wrong payload size, ignore\n");
                    free(payload);
                }
                do_open_close(sock, payload, type == LIBUSB_REDIR_OPEN_DEVICE);
                free(payload);
                break;
            case LIBUSB_REDIR_SUBMIT_TRANSFER:

                if(length < sizeof(struct libusb_redir_packet_submit_transfer))
                    dbg("submit_transfer request is too small ignore\n");
                else
                    submit_transfer(sock, payload, length);
                free(payload);
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
