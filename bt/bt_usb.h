/** @file bt_usb.h
  *  @brief This file contains USB (interface) related macros, enum, and structure.
  *
  *
  * Copyright 2014-2020, 2023 NXP
  *
  * This software file (the File) is distributed by NXP
  * under the terms of the GNU General Public License Version 2, June 1991
  * (the License).  You may use, redistribute and/or modify the File in
  * accordance with the terms and conditions of the License, a copy of which
  * is available by writing to the Free Software Foundation, Inc.,
  * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA or on the
  * worldwide web at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
  *
  * THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE
  * IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE
  * ARE EXPRESSLY DISCLAIMED.  The License provides additional details about
  * this warranty disclaimer.
  *
  */

#ifndef _BT_USB_H_
#define _BT_USB_H_

#include <linux/usb.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 24)
#define REFDATA __refdata
#else
#define REFDATA
#endif

/** CMD id for CMD4 */
#define FW_CMD_4     0x00000004
/** CMD id for CMD6 */
#define FW_CMD_6     0x00000006
/** CMD id for CMD7 */
#define FW_CMD_7     0x00000007
/** CMD id for CMD10 */
#define FW_CMD_10    0x0000000a
/** CMD id for CMD21 */
#define FW_CMD_21    0x00000015

#ifdef USB8997
/** USB 8997 VID 1 */
#define USB8997_VID_1   0x1286
/** USB 8997 PID 1 */
#define USB8997_PID_1   0x204d
/** USB 8997V2 PID 1 */
#define USB8997V2_PID_1 0x2052
/** USB 8997 PID 2 */
#define USB8997_PID_2   0x204E
/** USB8997 chip revision ID */
#define USB8997_Z	0x02
#define USB8997_V2	0x10
#endif /* USB8997 */

#ifdef USB8897
/** USB 8897 VID 1 */
#define USB8897_VID_1   0x1286
/** USB 8897 PID 1 */
#define USB8897_PID_1   0x2045
/** USB 8897 PID 2 */
#define USB8897_PID_2   0x2046
#endif /* USB8897 */

#ifdef USB8978
/** USB 8978 VID 1 */
#define USB8978_VID_1   0x1286
/** USB 8978 PID 1 */
#define USB8978_PID_1   0x2064
/** USB 8978 PID 2 */
#define USB8978_PID_2   0x2065
/* WLAN downloaded combo  firmware; register for BT enumeration */
#define USBUSB8978_PID_1_WLAN   0x2062
#define USB8978_PID_2_WLAN  0x2063
#endif /* USB8978 */

/** USB 9097 VID 1 */
#define USB9097_VID_1   0x1286
/** PCIEUSB 9097 PID 1 */
#define PCIEUSB9097_PID_1   0x2058
/** USBUSB 9097 PID 1 */
#define USBUSB9097_PID_1    0x2060
/** PCIEUSB 9097 PID 1 */
#define PCIEUSB9097_PID_2   0x2059
/** USBUSB 9097 PID 1 */
#define USBUSB9097_PID_2   0x2061

#ifdef USB9098
/** USB 9098 VID 1 */
#define USB9098_VID_1   0x1286
/** USBUSB 9098 PID 1 */
#define USBUSB9098_PID_1   0x2056
/** PCIEUSB 9098 PID 1 */
#define PCIEUSB9098_PID_1   0x2054
/** USBUSB 9098 PID 2 */
#define USBUSB9098_PID_2  0x2057
/** PCIEUSB 9098 PID 2 */
#define PCIEUSB9098_PID_2  0x2055
#endif /* USB9098 */

#ifdef USBIW610
/** USB IW610 VID 1 */
#define USBIW610_VID_1   0x0471
/** USB IW610 PID 1 */
#define USBIW610_PID_1   0x0214
#define USBIW610_PID_2   0x0215
#endif /* USBIW610 */

#ifdef USBIW624
/** USB IW624 VID 1 */
#define USBIW624_VID_1   0x0471
/** USBUSB IW624 PID 1 */
#define USBUSBIW624_PID_1   0x020C
/** USBUSB IW624 PID 2 */
#define USBUSBIW624_PID_2  0x020D
#endif /* USBIW624 */

/** Boot state: FW download */
#define USB_FW_DNLD 1
/** Boot state: FW ready */
#define USB_FW_READY 2

/* Transmit buffer size for chip revision check */
#define CHIP_REV_TX_BUF_SIZE    16
/* Receive buffer size for chip revision check */
#define CHIP_REV_RX_BUF_SIZE    2048

/* Extensions */
#define EXTEND_HDR       (0xAB95)
#define EXTEND_V1        (0x0001)

#define ALLOC_USB_BUF_SIZE  (MAX(MRVDRV_BT_RX_PACKET_BUFFER_SIZE, \
                        MRVDRV_SIZE_OF_CMD_BUFFER) + BT_HEADER_LEN)

/** bt_usb_ep */
typedef enum _bt_usb_ep {
	BT_USB_EP_CMD = 0,	/* Control Endpoint */
	BT_USB_EP_CMD_EVENT = 1,
	BT_USB_EP_EVENT = 3,	/* Interrupt Endpoint */
	BT_USB_EP_ACL_DATA = 4,	/* Bulk Endpoint */
	BT_USB_EP_SCO_DATA = 5,	/* Isochronous Endpoint */
} bt_usb_ep;

/** Timeout in milliseconds for usb_bulk_msg function */
#define BT_USB_BULK_MSG_TIMEOUT      100
/** Timeout in milliseconds for usb_control_msg function */
#define BT_USB_CTRL_MSG_TIMEOUT      100

/** Data Structures */
/** driver_buffer data structure */
typedef struct _bt_usb_buffer {
	/** Flags for this buffer */
	u32 flags;
	/** Buffer descriptor, e.g. skb in Linux */
	void *pdesc;
	/** Pointer to buffer */
	u8 *pbuf;
	/** Offset to data */
	u32 data_offset;
	/** Data length */
	u32 data_len;
} bt_usb_buffer, *pbt_usb_buffer;

/** Card-type detection frame response */
struct usb_chip_rev_resp {
	/** 32-bit ACK+WINNER field */
	u32 ack_winner;
	/** 32-bit Sequence number */
	u32 seq;
	/** 32-bit extend */
	u32 extend;
	/** 32-bit chip-revision code */
	u32 chip_rev;
};

/** USB card description structure*/
struct usb_card_rec {
	/** USB device */
	struct usb_device *udev;

	/** USB curr interface */
	struct usb_interface *intf;
	/** Rx data endpoint address */
	u8 rx_cmd_ep;

    /** Tx command endpoint address */
	u8 tx_cmd_ep;

    /** Bulk out max packet size */
	int bulk_out_maxpktsize;

	/** USB isoc interface */
	struct usb_interface *isoc;

	/** USB Tx URB anchor */
	struct usb_anchor tx_anchor;

    /** USB Rx Intr URB anchor */
	struct usb_anchor intr_anchor;

    /** USB Rx Bulk URB anchor */
	struct usb_anchor bulk_anchor;

    /** USB Rx Isoc URB anchor */
	struct usb_anchor isoc_anchor;

    /** Tx counter */
	int tx_in_flight;

    /** Tx lock */
	spinlock_t txlock;

    /** Rx lock */
	spinlock_t rxlock;

	/** current flags */
	unsigned long flags;

#ifdef USB_SCO_SUPPORT
	/** Isoc work */
	struct work_struct work;
#endif

	/** driver specific struct */
	void *priv;

	/** Flag to indicate boot state */
	u8 boot_state;

	/** Command request type */
	u8 cmdreq_type;
	/** Tx cmd bulk endpoint address */
	struct usb_endpoint_descriptor *bulk_cmd_ep;
	/** Rx Interrupt endpoint address */
	struct usb_endpoint_descriptor *intr_ep;

	/** Tx Bulk endpoint address */
	struct usb_endpoint_descriptor *bulk_tx_ep;

	/** Rx Bulk endpoint address */
	struct usb_endpoint_descriptor *bulk_rx_ep;

	/** Tx Isoc endpoint address */
	struct usb_endpoint_descriptor *isoc_tx_ep;

	/** Rx Isoc endpoint address */
	struct usb_endpoint_descriptor *isoc_rx_ep;

	/** SCO No. */
	unsigned int sco_num;

	/** Isoc Alt Setting*/
	int isoc_altsetting;
	/** iscoc if number */
	int isoc_ifnum;

    /** USB card type */
	int card_type;
#ifdef USB8997
    /** revision id */
	int revision_id;
#endif
};

/** usb_image data structure */
typedef struct _bt_usb_fw_image {
	/** Helper image buffer pointer */
	u8 *phelper_buf;
	/** Helper image length */
	u32 helper_len;
	/** Firmware image buffer pointer */
	u8 *pfw_buf;
	/** Firmware image length */
	u32 fw_len;
} bt_usb_fw_image, *pbt_usb_fw_image;

/** Tx buffer size for firmware download*/
#define FW_DNLD_TX_BUF_SIZE       2312
/** Rx buffer size for firmware download*/
#define FW_DNLD_RX_BUF_SIZE       2048
/** Max firmware retry */
#define MAX_FW_RETRY              3

/** Firmware has last block */
#define FW_HAS_LAST_BLOCK         0x00000004

/** Firmware data transmit size */
#define FW_DATA_XMIT_SIZE \
	(sizeof(FWHeader) + DataLength + sizeof(u32))

/** FWHeader */
typedef struct _FWHeader {
	/** FW download command */
	u32 dnld_cmd;
	/** FW base address */
	u32 base_addr;
	/** FW data length */
	u32 data_length;
	/** FW CRC */
	u32 crc;
} FWHeader;

/** FWData */
typedef struct _FWData {
	/** FW data header */
	FWHeader fw_header;
	/** FW data sequence number */
	u32 seq_num;
	/** FW data buffer */
	u8 data[1];
} FWData;

/** FWSyncHeader */
typedef struct _FWSyncHeader {
	/** FW sync header command */
	u32 cmd;
	/** FW sync header sequence number */
	u32 seq_num;
	/** Extended header */
	u32 magic;
	/** Chip rev */
	u32 chip_rev;
	/** Strap */
	u32 strap;
	/** Status */
	u32 status;
	/** Offset */
	u32 offset;
} FWSyncHeader;

#endif /* _BT_USB_H_ */
