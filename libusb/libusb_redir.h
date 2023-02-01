#ifndef LIBUSB_REDIR_H
#define LIBUSB_REDIR_H

#include "libusb.h"
#include "libusbi.h"

/* FIXME should specify LE/BE for network, also same for USB */

enum libusb_redir_packet_type
{
    /* ask for a device list */
    LIBUSB_REDIR_REQUEST_DEVICE_LIST = 0,
    /* provide a device list */
    LIBUSB_REDIR_DEVICE_LIST = 1,
    /* ask for a device descriptor */
    LIBUSB_REDIR_REQUEST_DEVICE_DESCRIPTOR = 2,
    /* provide a device descriptor */
    LIBUSB_REDIR_DEVICE_DESCRIPTOR = 3,
    /* ask for the active config descriptor */
    LIBUSB_REDIR_REQUEST_ACTIVE_CONFIG_DESCRIPTOR = 4,
    /* ask for a specific config descriptor */
    LIBUSB_REDIR_REQUEST_CONFIG_DESCRIPTOR = 5,
    /* provide a config descriptor */
    LIBUSB_REDIR_CONFIG_DESCRIPTOR = 6,
    /* open/close a device */
    LIBUSB_REDIR_OPEN_DEVICE = 7,
    LIBUSB_REDIR_OPEN_STATUS = 8,
    LIBUSB_REDIR_CLOSE_DEVICE = 9,
    /* submit transfer */
    LIBUSB_REDIR_SUBMIT_TRANSFER = 10,
    LIBUSB_REDIR_TRANSFER_STATUS = 11,
} LIBUSB_PACKED;

/* every packet starts with this header */
struct libusb_redir_packet_header
{
    uint32_t type; /* libusb_redir_packet_type */
    uint32_t length; /* length of payload (exclude this header) */
} LIBUSB_PACKED;

struct libusb_redir_packet_dev_list_entry
{
    uint32_t device_id; /* unique ID generated by host */
    uint8_t bus_number;
    uint8_t port_number;
    uint8_t device_address;
} LIBUSB_PACKED;

/* for LIBUSB_REDIR_DEVICE_DESCRIPTOR */
struct libusb_redir_packet_dev_list
{
    uint32_t nr_devices; /* number of devices */
    struct libusb_redir_packet_dev_list_entry device[0]; /* devices */
} LIBUSB_PACKED;

/* for LIBUSB_REDIR_REQUEST_DEVICE_DESCRIPTOR */
struct libusb_redir_packet_get_dev_desc
{
    uint32_t device_id;
} LIBUSB_PACKED;

/* for LIBUSB_REDIR_DEVICE_DESCRIPTOR */
struct libusb_redir_packet_dev_desc
{
    uint32_t device_id;
    struct usbi_device_descriptor desc;
} LIBUSB_PACKED;

/* for LIBUSB_REDIR_REQUEST_ACTIVE_CONFIG_DESCRIPTOR */
struct libusb_redir_packet_get_active_config_desc
{
    uint32_t device_id;
} LIBUSB_PACKED;

/* for LIBUSB_REDIR_REQUEST_CONFIG_DESCRIPTOR */
struct libusb_redir_packet_get_config_desc
{
    uint32_t device_id;
    uint8_t config_index;
} LIBUSB_PACKED;

/* for LIBUSB_REDIR_CONFIG_DESCRIPTOR */
struct libusb_redir_packet_config_desc
{
    uint32_t device_id;
    struct usbi_configuration_descriptor desc[0]; /* the size is variable, this is just the header */
} LIBUSB_PACKED;

/* LIBUSB_REDIR_{OPEN,CLOSE}_DEVICE */
struct libusb_redir_packet_open_close
{
    uint32_t device_id;
} LIBUSB_PACKED;

/* LIBUSB_REDIR_OPEN_STATUS */
struct libusb_redir_packet_open_status
{
    uint32_t device_id;
    uint32_t status; /* minus a value of enum libusb_error */
} LIBUSB_PACKED;

/* LIBUSB_REDIR_SUBMIT_TRANSFER */
struct libusb_redir_packet_submit_transfer
{
    uint32_t device_id;
    uint32_t transfer_id; /* transfer ID generated by the client */
    uint32_t timeout; /* in milliseconds, 0 for infinity */
    uint32_t length; /* this is the data length in/out, includes SETUP packet size */
    uint8_t endpoint; /* indicate direction in bit 7 even for control */
    uint8_t type; /* libusb_transfer_type */
    /* followed by setup packet for control transfers */
    /* followed by data for OUT transfers */
} LIBUSB_PACKED;

/* LIBUSB_REDIR_TRANSFER_STATUS */
struct libusb_redir_packet_transfer_status
{
    uint32_t device_id;
    uint32_t transfer_id;
    uint32_t status;
    uint32_t length; /* for OUT, actually transfered size, for IN size of following data */
    /* followed by data for IN transfers */
} LIBUSB_PACKED;

#endif /* LIBUSB_REDIR_H */
