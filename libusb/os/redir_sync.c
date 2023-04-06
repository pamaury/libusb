/*
 * Copyright © 2013 Amaury Pouly <amaury.pouly@lowrisc.org>
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

#include "libusbi.h"
#include "libusb_redir.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>

struct redir_context_priv
{
    /* FIXME protect this by a lock */
    int socket; /* the socket to talk to the server */
};

struct redir_device_priv
{
    /* unique ID for the device (generated by host) */
    uint32_t device_id;
    uint32_t next_transfer_id;
};

struct redir_transfer_priv
{
    /* unique ID for the transfer */
    uint32_t transfer_id;
    /* transfer status */
    enum libusb_transfer_status status;
};

static void init_device_priv(struct redir_device_priv *priv)
{
    priv->device_id = 0;
    priv->next_transfer_id = 19;
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
static int send_packet(struct libusb_context *ctx,
                       enum libusb_redir_packet_type type,
                       const void *packet, size_t length)
{
    usbi_dbg(ctx, "sending packet type %lu, length %lu", (unsigned long)type, (unsigned long)length);
    struct redir_context_priv *priv = usbi_get_context_priv(ctx);
    struct libusb_redir_packet_header hdr;
    hdr.type = type;
    hdr.length = length; /* truncate, check length */
    int err = write_or_die(priv->socket, &hdr, sizeof(hdr));
    if(err < 0)
        return err;
    /* handle empty payload */
    if(packet == 0 || length == 0)
        return 0;
    return write_or_die(priv->socket, packet, length);
}

/* super ugly, wait for a packet of a specific type and return the payload
 * if the pointer is NULL, it will be allocated by the function
 * otherwise the length is the allocated length and be reduce to the actually received one
 * return 0 on success */
static int wait_packet(struct libusb_context *ctx,
                       enum libusb_redir_packet_type expected_type,
                       void **packet, size_t *inout_length)
{
    usbi_dbg(ctx, "wait for packet type %lu", (unsigned long)expected_type);
    struct redir_context_priv *priv = usbi_get_context_priv(ctx);
    struct libusb_redir_packet_header hdr;

    while(true)
    {
        int err = read_or_die(priv->socket, &hdr, sizeof(hdr));
        if(err < 0)
            return err;
        usbi_dbg(ctx, "  got packet type %lu length %lu", (unsigned long)hdr.type, (unsigned long)hdr.length);
        /* FIXME prevent attacker controlled allocation here */
        void *payload = malloc(hdr.length);
        if(payload == NULL)
            return LIBUSB_ERROR_NO_MEM;
        err = read_or_die(priv->socket, payload, hdr.length);
        if(err < 0)
        {
            free(payload);
            return err;
        }
        usbi_dbg(ctx, "  got packet data");
        if(hdr.type == expected_type)
        {
            if(*packet == NULL)
            {
                *packet = payload;
                *inout_length = hdr.length;
                return LIBUSB_SUCCESS;
            }
            else
            {
                if(hdr.length > *inout_length)
                {
                    free(payload);
                    return LIBUSB_ERROR_NO_MEM; /* buffer too small */
                }
                memcpy(*packet, payload, hdr.length);
                *inout_length = hdr.length;
                free(payload);
                return LIBUSB_SUCCESS;
            }
        }
        else
        {
            usbi_dbg(ctx, "  not the expected type, ignore packet");
            free(payload);
        }
    }
}

static int connect_unix_socket(struct libusb_context *ctx, const char *name)
{
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if(sock == -1)
    {
        usbi_err(ctx, "error: could not create unix socket: %s", strerror(errno));
        return -1;
    }
    struct sockaddr_un sockaddr;
    sockaddr.sun_family = AF_UNIX;
    if(strlen(name) + 1 > sizeof(sockaddr.sun_path))
    {
        usbi_err(ctx, "error: unix socket name is too long");
        close(sock);
        return -1;
    }
    strcpy(sockaddr.sun_path, name);
    /* if the first character of name is @, create an abstract socket */
    if(name[0] == '@')
        sockaddr.sun_path[0] = 0; /* creates an abstract socket */
    int err = connect(sock, (struct sockaddr*)&sockaddr, sizeof(sockaddr.sun_family) + strlen(name));
    if(err != 0)
    {
        usbi_err(ctx, "error: could not connect socket: %s", strerror(errno));
        close(sock);
        return -1;
    }
    return sock;
}

static int redir_init(struct libusb_context *ctx)
{
    struct redir_context_priv *priv = usbi_get_context_priv(ctx);
    usbi_dbg(ctx, "init redir");
    priv->socket = connect_unix_socket(ctx, "@libusb_redir");
    usbi_dbg(ctx, "  socket: %d\n", priv->socket);
    return LIBUSB_SUCCESS;
}

static void redir_exit(struct libusb_context *ctx)
{
    usbi_dbg(ctx, "exit redir");
}

static void fill_dev_desc(struct libusb_device_descriptor*desc_out, struct usbi_device_descriptor* desc_in)
{
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
    usbi_localize_device_descriptor(desc_out);
}

static int
redir_get_device_list(struct libusb_context * ctx,
    struct discovered_devs **discdevs)
{
    /* ask for device list */
    int err = send_packet(ctx, LIBUSB_REDIR_REQUEST_DEVICE_LIST, NULL, 0);
    if(err < 0)
        return err;
    /* receive list */
    struct libusb_redir_packet_dev_list *dev_list = NULL;
    size_t dev_list_len;
    err = wait_packet(ctx, LIBUSB_REDIR_DEVICE_LIST, &dev_list, &dev_list_len);
    if(err < 0)
        return err;
    /* TODO proper check on length */
    size_t expected_dev_list_size = sizeof(struct libusb_redir_packet_dev_list);
    expected_dev_list_size += dev_list->nr_devices * sizeof(struct libusb_redir_packet_dev_list_entry);
    if(dev_list_len != expected_dev_list_size)
    {
        usbi_err(ctx, "device list has the wrong size: %lu for %lu devices, expected %lu\n",
            (unsigned long)dev_list_len, (unsigned long)dev_list->nr_devices,
            (unsigned long)expected_dev_list_size);
        free(dev_list);
        return LIBUSB_ERROR_OTHER;
    }
    for(size_t i = 0; i < dev_list->nr_devices; i++)
    {
        unsigned long session_id = dev_list->device[i].device_id;
        struct libusb_device *dev = usbi_get_device_by_session_id(ctx, session_id);
        /* new device? */
        if(dev == NULL)
        {
            dev = usbi_alloc_device(ctx, session_id);
            struct redir_device_priv *dev_priv = usbi_get_device_priv(dev);
            init_device_priv(dev_priv);
            dev_priv->device_id = dev_list->device[i].device_id;
            dev->bus_number = dev_list->device[i].bus_number;
            dev->port_number = dev_list->device[i].port_number;
            dev->device_address = dev_list->device[i].device_address;
            usbi_info(ctx, "new device dev_id=%lx, bus=%u, port=%u, addr=%u",
                (unsigned long)dev_priv->device_id, (unsigned)dev->bus_number,
                (unsigned)dev->port_number, (unsigned)dev->device_address);
            /* ask device descriptor */
            struct libusb_redir_packet_get_dev_desc req;
            req.device_id = dev_priv->device_id;
            err = send_packet(ctx, LIBUSB_REDIR_REQUEST_DEVICE_DESCRIPTOR, &req, sizeof(req));
            if(err < 0)
            {
                libusb_unref_device(dev);
                return err;
            }
            /* receive list */
            struct libusb_redir_packet_dev_desc dev_desc;
            size_t dev_desc_len = sizeof(dev_desc);
            struct libusb_redir_packet_dev_desc *dev_desc_ptr = &dev_desc;
            err = wait_packet(ctx, LIBUSB_REDIR_DEVICE_DESCRIPTOR, &dev_desc_ptr, &dev_desc_len);
            if(err < 0 || dev_desc_len != sizeof(dev_desc) || dev_desc.device_id != dev_priv->device_id)
            {
                libusb_unref_device(dev);
                return err;
            }
            usbi_dbg(ctx, "got device descriptor\n");
            fill_dev_desc(&dev->device_descriptor, &dev_desc.desc);
            /* sanitize device */
            if(usbi_sanitize_device(dev) < 0)
            {
                libusb_unref_device(dev);
                continue;
            }
        }
        *discdevs = discovered_devs_append(*discdevs, dev);
    }
    return LIBUSB_SUCCESS;
}

static int
redir_get_active_config_descriptor(struct libusb_device *dev,
    void *buf, size_t len)
{
    // struct libusb_context *ctx = usbi_get_context_priv(dev->ctx);
    // struct redir_device_priv *dev_priv = usbi_get_device_priv(dev);
    // usbi_dbg(ctx, "get active config descriptor for device id %lx", (unsigned long)dev_priv->device_id);
    // /* this should really be cached but we don't at the moment */
    // struct libusb_redir_packet_get_active_config_desc req;
    // req.device_id = dev_priv->device_id;
    // int err = send_packet(ctx, LIBUSB_REDIR_REQUEST_ACTIVE_CONFIG_DESCRIPTOR, &req, sizeof(req));
    // if(err < 0)
    // {
    //     usbi_err(ctx, "cannot get active config descriptor\n");
    //     return err;
    // }
    // struct libusb_redir_packet_dev_desc config_desc;
    // size_t config_desc_sz = sizeof(config_desc);
    // struct libusb_redir_packet_dev_desc *config_desc_ptr = &config_desc;
    // err = wait_packet(ctx, LIBUSB_REDIR_CONFIG_DESCRIPTOR, &config_desc_ptr, &config_desc_sz);
    // if(err < 0 || config_desc_sz != sizeof(config_desc) || config_desc.device_id != dev_priv->device_id)
    //     return err;
    // usbi_dbg(ctx, "got active config descriptor\n");
    // /* TODO check length */
    // memcpy(buf, &config_desc.desc, len);
    //
    // return LIBUSB_SUCCESS;
    return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int
redir_get_config_descriptor(struct libusb_device *dev, uint8_t idx,
    void *buf, size_t len)
{
    struct redir_device_priv *dev_priv = usbi_get_device_priv(dev);
    usbi_dbg(dev->ctx, "get config descriptor %x for device id %lx", (unsigned)idx, (unsigned long)dev_priv->device_id);
    /* this should really be cached but we don't at the moment */
    struct libusb_redir_packet_get_config_desc req;
    req.device_id = dev_priv->device_id;
    req.config_index = idx;
    int err = send_packet(dev->ctx, LIBUSB_REDIR_REQUEST_CONFIG_DESCRIPTOR, &req, sizeof(req));
    if(err < 0)
    {
        usbi_err(dev->ctx, "cannot get config descriptor\n");
        return err;
    }
    size_t config_desc_sz = 0;
    struct libusb_redir_packet_config_desc *config_desc_ptr = NULL;
    err = wait_packet(dev->ctx, LIBUSB_REDIR_CONFIG_DESCRIPTOR, &config_desc_ptr, &config_desc_sz);
    if(err < 0 || config_desc_ptr->device_id != dev_priv->device_id)
        return err;
    usbi_dbg(dev->ctx, "got config descriptor\n");
    size_t copy_len = MIN(len, config_desc_sz-sizeof(struct libusb_redir_packet_config_desc));
    memcpy(buf, &config_desc_ptr->desc, copy_len);
    return copy_len;
}

static int
redir_open(struct libusb_device_handle *handle)
{
    struct redir_device_priv *dev_priv = usbi_get_device_priv(handle->dev);
    usbi_dbg(handle->dev->ctx, "open device id %lx", (unsigned long)dev_priv->device_id);
    struct libusb_redir_packet_open_close req;
    req.device_id = dev_priv->device_id;
    int err = send_packet(handle->dev->ctx, LIBUSB_REDIR_OPEN_DEVICE, &req, sizeof(req));
    if(err < 0)
    {
        usbi_err(handle->dev->ctx, "cannot open device\n");
        return err;
    }
    struct libusb_redir_packet_open_status status;
    size_t status_size = sizeof(status);
    struct libusb_redir_packet_open_status *status_ptr = &status;
    err = wait_packet(handle->dev->ctx, LIBUSB_REDIR_OPEN_STATUS, &status_ptr, &status_size);
    if(err < 0 || status_size != sizeof(status) || status.device_id != dev_priv->device_id)
        return err;
    usbi_dbg(handle->dev->ctx, "device open status: %d\n", status.status);
    return -status.status;
}

static void
redir_close(struct libusb_device_handle *handle)
{
    struct redir_device_priv *dev_priv = usbi_get_device_priv(handle->dev);
    usbi_dbg(handle->dev->ctx, "close device id %lx", (unsigned long)dev_priv->device_id);
    struct libusb_redir_packet_open_close req;
    req.device_id = dev_priv->device_id;
    int err = send_packet(handle->dev->ctx, LIBUSB_REDIR_CLOSE_DEVICE, &req, sizeof(req));
    if(err < 0)
    {
        usbi_err(handle->dev->ctx, "cannot close device\n");
        return err;
    }
    return LIBUSB_SUCCESS;
}

static int
redir_set_configuration(struct libusb_device_handle *handle, int config)
{
    usbi_err(HANDLE_CTX(handle), "redir_set_configuration not implemented");
    return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int
redir_claim_interface(struct libusb_device_handle *handle, uint8_t iface)
{
    usbi_err(HANDLE_CTX(handle), "redir_claim_interface not implemented");
    return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int
redir_release_interface(struct libusb_device_handle *handle, uint8_t iface)
{
    usbi_err(HANDLE_CTX(handle), "redir_release_interface not implemented");
    return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int
redir_set_interface_altsetting(struct libusb_device_handle *handle, uint8_t iface,
    uint8_t altsetting)
{
    usbi_err(HANDLE_CTX(handle), "redir_set_interface_altsetting not implemented");
    return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int
redir_clear_halt(struct libusb_device_handle *handle, unsigned char endpoint)
{
    usbi_err(HANDLE_CTX(handle), "redir_clear_halt not implemented");
    return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int
redir_submit_transfer(struct usbi_transfer *itransfer)
{
    libusb_context *ctx = ITRANSFER_CTX(itransfer);
    struct redir_device_priv *dev_priv = usbi_get_device_priv(itransfer->dev);
    struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
    struct redir_transfer_priv *xfer_priv = usbi_get_transfer_priv(itransfer);

    /* this code only works for control, bulk and interrupt */
    switch(transfer->type)
    {
        case LIBUSB_TRANSFER_TYPE_CONTROL:
        case LIBUSB_TRANSFER_TYPE_BULK:
        case LIBUSB_TRANSFER_TYPE_INTERRUPT:
            break;
        default:
            return LIBUSB_ERROR_NOT_SUPPORTED;
    }

    /* debug */
    bool is_in = !!((transfer->endpoint & LIBUSB_ENDPOINT_IN));
    /* for control transfers, we need to look at the setup packet */
    if(transfer->type == LIBUSB_TRANSFER_TYPE_CONTROL)
    {
        struct libusb_control_setup *setup = libusb_control_transfer_get_setup(transfer);
        is_in = !!(setup->bmRequestType & LIBUSB_ENDPOINT_IN);
    }
    /* ID */
    xfer_priv->transfer_id = dev_priv->next_transfer_id++;

    usbi_dbg(ctx, "submit transfer: id=%lu, endp=%x (EP%d %s), length=%lu",
             xfer_priv->transfer_id,
             transfer->endpoint,
             transfer->endpoint & LIBUSB_ENDPOINT_ADDRESS_MASK,
             is_in ? "IN" : "OUT",
             (unsigned long)transfer->length);

    /* compute size */
    size_t req_size = sizeof(struct libusb_redir_packet_submit_transfer);
    /* for OUT transfer, the length is all the data sent (including setup for control) */
    if(!is_in)
        req_size += transfer->length;
    /* for IN control transfer, we need to at least send the setup */
    else if(transfer->type == LIBUSB_TRANSFER_TYPE_CONTROL)
        req_size += LIBUSB_CONTROL_SETUP_SIZE;
    /* allocate and fill request */
    struct libusb_redir_packet_submit_transfer *req = malloc(req_size);
    req->device_id = dev_priv->device_id;
    req->transfer_id = xfer_priv->transfer_id;
    req->timeout = transfer->timeout;
    req->endpoint = transfer->endpoint | (is_in ? LIBUSB_ENDPOINT_IN : 0); /* libusb does not set bit 7 for control in */
    req->type = transfer->type;
    req->length = transfer->length;
    /* copy data */
    void *buffer = (req + 1);
    if(!is_in)
        memcpy(buffer, transfer->buffer, transfer->length);
    else if(transfer->type == LIBUSB_TRANSFER_TYPE_CONTROL)
        memcpy(buffer, transfer->buffer, LIBUSB_CONTROL_SETUP_SIZE);
    /* send request */
    int err = send_packet(ctx, LIBUSB_REDIR_SUBMIT_TRANSFER, req, req_size);
    free(req);
    if(err < 0)
    {
        usbi_err(ctx, "cannot submit transfer\n");
        return err;
    }
    /* wait for result */
    struct libusb_redir_packet_transfer_status *status = NULL;
    size_t status_len;
    err = wait_packet(ctx, LIBUSB_REDIR_TRANSFER_STATUS, &status, &status_len);
    if(err < 0)
    {
        usbi_err(ctx, "cannot get transfer status\n");
        return err;
    }
    usbi_dbg(ctx, "got status: status_len=%lu, status->len=%lu", status_len, status->length);
    if(dev_priv->device_id != status->device_id ||
            xfer_priv->transfer_id != status->transfer_id)
    {
        usbi_err(ctx, "transfer status has unexpected dev_id=%d/xfer_id=%d\n", status->device_id, status->transfer_id);
        free(status);
        return LIBUSB_ERROR_OTHER;
    }
    size_t expected_len = status->length + sizeof(struct libusb_redir_packet_transfer_status);
    if(status_len != expected_len)
    {
        usbi_err(ctx, "transfer status has unexpected size %lu (expected %lu)\n", status_len, expected_len);
        free(status);
        return LIBUSB_ERROR_OTHER;
    }
    xfer_priv->status = status->status;
    usbi_dbg(ctx, "transfer status: %lu\n", status->status);
    itransfer->transferred = 0;
    if(status->status == LIBUSB_SUCCESS)
    {
        /* copy data back */
        if(status->length > transfer->length)
        {
            usbi_err(ctx, "got more data back than expected!");
            xfer_priv->status = LIBUSB_TRANSFER_OVERFLOW;
        }
        else
        {
            memcpy(transfer->buffer, status + 1, status->length);
            itransfer->transferred = status->length;
        }
    }
    /* the usbi doc says we have to call usbi_signal_transfer_completion()
     * to make libusb call into the handle_transfer_completion. I am assuming
     * that it is safe to call it from here: submit_transfer is called
     * with flying_lock but usbi_signal_transfer_completion only uses the
     * event_data lock so it should be ok */
    usbi_signal_transfer_completion(itransfer);
    free(status);
    return LIBUSB_SUCCESS;
}

static int
redir_cancel_transfer(struct usbi_transfer *itransfer)
{
    return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int
redir_handle_transfer_completion(struct usbi_transfer *itransfer)
{
    struct redir_transfer_priv *xfer_priv = usbi_get_transfer_priv(itransfer);
    usbi_dbg(ITRANSFER_CTX(itransfer), "handle transfer completion: status=%lu\n", xfer_priv->status);
    return usbi_handle_transfer_completion(itransfer, xfer_priv->status);
}

const struct usbi_os_backend usbi_backend = {
    .name = "Redirect backend",
    .caps = 0,
    .init = redir_init,
    .exit = redir_exit,
    .get_device_list = redir_get_device_list,
    .open = redir_open,
    .close = redir_close,
    .get_active_config_descriptor = redir_get_active_config_descriptor,
    .get_config_descriptor = redir_get_config_descriptor,
    .set_configuration = redir_set_configuration,
    .claim_interface = redir_claim_interface,
    .release_interface = redir_release_interface,
    .set_interface_altsetting = redir_set_interface_altsetting,
    .clear_halt = redir_clear_halt,
    .submit_transfer = redir_submit_transfer,
    .cancel_transfer = redir_cancel_transfer,
    .handle_transfer_completion = redir_handle_transfer_completion,

    .context_priv_size = sizeof(struct redir_context_priv),
    .device_priv_size = sizeof(struct redir_device_priv),
    .transfer_priv_size = sizeof(struct redir_transfer_priv)
};


