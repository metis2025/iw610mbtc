/** @file bt_usb.c
  *  @brief This file contains USB (interface) related functions.
  *
  *
  * Copyright (C) 2005-2008 Marcel Holtmann <marcel@holtmann.org>
  *
  * Copyright 2014-2021, 2023 NXP
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

#include <linux/firmware.h>

#include "bt_drv.h"
#include "bt_usb.h"

extern bt_private *m_priv[];

/********************************************************
		Local Variables
********************************************************/

/** NXP USB device */
#define NXP_USB_DEVICE(vid, pid, name) \
	USB_DEVICE(vid, pid),\
	.driver_info = (t_ptr)name

/** NXP USB device and interface */
#define NXP_USB_DEVICE_AND_IFACE(vid, pid, cl, sc, pr, name) \
	USB_DEVICE_AND_INTERFACE_INFO(vid, pid, cl, sc, pr),\
	.driver_info = (t_ptr)name

/** Name of the USB driver */
static const char usbdriver_name[] = "bt-usbxxx";

/** This structure contains the device signature */
struct usb_device_id bt_usb_table[] = {

	/* Enter the device signature inside */
#ifdef USB8997
	{NXP_USB_DEVICE(USB8997_VID_1, USB8997_PID_1,
			"NXP BT USB Adapter")},
	{NXP_USB_DEVICE(USB8997_VID_1, USB8997V2_PID_1,
			"NXP BT USB Adapter")},
	{NXP_USB_DEVICE_AND_IFACE(USB8997_VID_1, USB8997_PID_2,
				  USB_CLASS_WIRELESS_CONTROLLER, 1, 1,
				  "NXP BT USB Adapter")},
#endif
#ifdef USB8978
	{NXP_USB_DEVICE(USB8978_VID_1, USB8978_PID_1,
			"NXP BT USB Adapter")},
	{NXP_USB_DEVICE(USB8978_VID_1, USBUSB8978_PID_1_WLAN,
			"NXP BT USB Adapter")},
	{NXP_USB_DEVICE_AND_IFACE(USB8978_VID_1, USB8978_PID_2,
				  USB_CLASS_WIRELESS_CONTROLLER, 1, 1,
				  "NXP BT USB Adapter")},
	{NXP_USB_DEVICE_AND_IFACE(USB8978_VID_1, USB8978_PID_2_WLAN,
				  USB_CLASS_WIRELESS_CONTROLLER, 1, 1,
				  "NXP BT USB Adapter")},
#endif
#ifdef USB8897
	{NXP_USB_DEVICE(USB8897_VID_1, USB8897_PID_1,
			"NXP BT USB Adapter")},
	{NXP_USB_DEVICE_AND_IFACE(USB8897_VID_1, USB8897_PID_2,
				  USB_CLASS_WIRELESS_CONTROLLER, 1, 1,
				  "NXP BT USB Adapter")},
#endif
	{NXP_USB_DEVICE(USB9097_VID_1, USBUSB9097_PID_1,
			"NXP BT USB Adapter")},
	{NXP_USB_DEVICE(USB9097_VID_1, PCIEUSB9097_PID_1,
			"NXP BT USB Adapter")},
	{NXP_USB_DEVICE_AND_IFACE(USB9097_VID_1, USBUSB9097_PID_2,
				  USB_CLASS_WIRELESS_CONTROLLER, 1, 1,
				  "NXP BT USB Adapter")},
	{NXP_USB_DEVICE_AND_IFACE(USB9097_VID_1, PCIEUSB9097_PID_2,
				  USB_CLASS_WIRELESS_CONTROLLER, 1, 1,
				  "NXP BT USB Adapter")},
#ifdef USB9098
	{NXP_USB_DEVICE(USB9098_VID_1, USBUSB9098_PID_1,
			"NXP BT USB Adapter")},
	{NXP_USB_DEVICE(USB9098_VID_1, PCIEUSB9098_PID_1,
			"NXP BT USB Adapter")},
	{NXP_USB_DEVICE_AND_IFACE(USB9098_VID_1, USBUSB9098_PID_2,
				  USB_CLASS_WIRELESS_CONTROLLER, 1, 1,
				  "NXP BT USB Adapter")},
	{NXP_USB_DEVICE_AND_IFACE(USB9098_VID_1, PCIEUSB9098_PID_2,
				  USB_CLASS_WIRELESS_CONTROLLER, 1, 1,
				  "NXP BT USB Adapter")},
#endif
#ifdef USBIW610
	{NXP_USB_DEVICE(USBIW610_VID_1, USBIW610_PID_1,
			"NXP BT USB Adapter")},
	{NXP_USB_DEVICE_AND_IFACE(USBIW610_VID_1, USBIW610_PID_2,
				  USB_CLASS_WIRELESS_CONTROLLER, 1, 1,
				  "NXP BT USB Adapter")},
#endif
#ifdef USBIW624
	{NXP_USB_DEVICE(USBIW624_VID_1, USBUSBIW624_PID_1,
			"NXP BT USB Adapter")},
	{NXP_USB_DEVICE_AND_IFACE(USBIW624_VID_1, USBUSBIW624_PID_2,
				  USB_CLASS_WIRELESS_CONTROLLER, 1, 1,
				  "NXP BT USB Adapter")},
#endif
	/* Terminating entry */
	{},
};

static int bt_usb_probe(struct usb_interface *intf,
			const struct usb_device_id *id);
static void bt_usb_disconnect(struct usb_interface *intf);
static int bt_usb_suspend(struct usb_interface *intf, pm_message_t message);
static int bt_usb_resume(struct usb_interface *intf);
static int usb_download_firmware_w_helper(bt_private *priv);
static int sbi_usb_wakeup_firmware(bt_private *priv);

/** bt_usb_driver */
static struct usb_driver REFDATA bt_usb_driver = {
	/* Driver name */
	.name = usbdriver_name,

	/* Probe function name */
	.probe = bt_usb_probe,

	/* Disconnect function name */
	.disconnect = bt_usb_disconnect,

	/* Device signature table */
	.id_table = bt_usb_table,

	/* Suspend function name */
	.suspend = bt_usb_suspend,

	/* Resume function name */
	.resume = bt_usb_resume,

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19)
	/* Driver supports autosuspend */
	.supports_autosuspend = 1,
#endif
};

MODULE_DEVICE_TABLE(usb, bt_usb_table);
static bt_if_ops usb_ops;
static int sbi_usb_register_dev(bt_private *priv);
static int sbi_usb_unregister_dev(bt_private *priv);

#ifdef USB8997
#define USB8997_DEFAULT_FW_NAME "nxp/usbusb8997_combo_v4.bin"
#define USB8997_DEFAULT_BT_FW_NAME "nxp/usb8997_bt_v4.bin"
#endif /* USB8997 */

#ifdef USB8978
#define USB8978_DEFAULT_FW_NAME "nxp/usbusbiw416_combo.bin"
#define USB8978_DEFAULT_BT_FW_NAME "nxp/usbiw416_bt.bin"
#endif /* USB8978 */

#ifdef USB9098
#define USB9098_Z1Z2        0x0
#define USB9098_A0          0x1
#define USB9098_A1          0x2
#define USB9098_DEFAULT_FW_NAME "nxp/usbusb9098_combo.bin"
#define PCIEUSB9098_DEFAULT_FW_NAME "nxp/pcieusb9098_combo.bin"
#define USB9098_DEFAULT_BT_FW_NAME "nxp/usb9098_bt.bin"
#define USB9098_V1_FW_NAME "nxp/usbusb9098_combo_v1.bin"
#define PCIEUSB9098_V1_FW_NAME "nxp/pcieusb9098_combo_v1.bin"
#define USB9098_BT_V1_FW_NAME "nxp/usb9098_bt_v1.bin"
#endif /* USB9098 */

#ifdef USBIW624
#define USBIW624_DEFAULT_FW_NAME "nxp/usbusbiw624_combo.bin"
#define USBIW624_DEFAULT_BT_FW_NAME "nxp/usbiw624_bt.bin"
#endif /* USBIW624 */

#ifdef USBIW610
#define USBIW610_DEFAULT_FW_NAME "nxp/usbusbiw610_combo.bin"
#define USBIW610_DEFAULT_BT_FW_NAME "nxp/usbiw610_bt.bin"
#endif /* USBIW610 */

#define USB9097_BT_A0        0x00
#define USB9097_BT_B0        0x01
#define USB9097_BT_B1        0x02
#define USB9097_DEFAULT_FW_NAME "nxp/usbusbiw620_combo.bin"
#define PCIEUSB9097_DEFAULT_FW_NAME "nxp/pcieusbiw620_combo.bin"
#define USB9097_DEFAULT_BT_FW_NAME "nxp/usbiw620_bt.bin"
#define USB9097_V1_FW_NAME "nxp/usbusbiw620_combo_v1.bin"
#define PCIEUSB9097_V1_FW_NAME "nxp/pcieusbiw620_combo_v1.bin"
#define USB9097_BT_V1_FW_NAME "nxp/usbiw620_bt_v1.bin"

#ifdef USB8897
#define USB8897_DEFAULT_FW_NAME "nxp/usb8897_uapsta.bin"
#define USB8897_DEFAULT_BT_FW_NAME "nxp/usb8897_bt.bin"
#endif /* USB8897 */

#define BT_USB_MAX_ISOC_FRAMES	10

#define BT_USB_INTR_RUNNING	0
#define BT_USB_BULK_RUNNING	1
#define BT_USB_ISOC_RUNNING	2
#define BT_USB_SUSPENDING	3

#define BT_USB_DID_ISO_RESUME	4

#ifdef USB8897
static struct _card_info card_info_usb8897 = {
	.fw_name = USB8897_DEFAULT_FW_NAME,
	.fw_name_bt = USB8897_DEFAULT_BT_FW_NAME,
};
#endif
#ifdef USB8997
static struct _card_info card_info_usb8997 = {
	.fw_name = USB8997_DEFAULT_FW_NAME,
	.fw_name_bt = USB8997_DEFAULT_BT_FW_NAME,
};
#endif

#ifdef USB8978
static struct _card_info card_info_usb8978 = {
	.fw_name = USB8978_DEFAULT_FW_NAME,
	.fw_name_bt = USB8978_DEFAULT_BT_FW_NAME,
};
#endif

#ifdef USB9098
static struct _card_info card_info_usb9098 = {
	.fw_name = USB9098_DEFAULT_FW_NAME,
	.fw_name_bt = USB9098_DEFAULT_BT_FW_NAME,
};

static struct _card_info card_info_pcieusb9098 = {
	.fw_name = PCIEUSB9098_DEFAULT_FW_NAME,
	.fw_name_bt = USB9098_DEFAULT_BT_FW_NAME,
};
#endif

static struct _card_info card_info_usb9097 = {
	.fw_name = USB9097_DEFAULT_FW_NAME,
	.fw_name_bt = USB9097_DEFAULT_BT_FW_NAME,
};

static struct _card_info card_info_pcieusb9097 = {
	.fw_name = PCIEUSB9097_DEFAULT_FW_NAME,
	.fw_name_bt = USB9097_DEFAULT_BT_FW_NAME,
};

#ifdef USBIW610
static struct _card_info card_info_usbiw610 = {
	.fw_name = USBIW610_DEFAULT_FW_NAME,
	.fw_name_bt = USBIW610_DEFAULT_BT_FW_NAME,
};
#endif

#ifdef USBIW624
static struct _card_info card_info_usbiw624 = {
	.fw_name = USBIW624_DEFAULT_FW_NAME,
	.fw_name_bt = USBIW624_DEFAULT_BT_FW_NAME,
};
#endif

/********************************************************
		Global Variables
********************************************************/

extern char mbt_driver_version[];

/********************************************************
		Local Fucntions
********************************************************/

/**
 *  @brief This function get sdio device from card type
 *
 *  @param pmadapter  A pointer to mlan_adapter structure
 *  @return           MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
static int
sbi_get_usb_device(bt_private *priv)
{
	int ret = BT_STATUS_SUCCESS;
	u16 card_type = priv->adapter->card_type;

	ENTER();

	switch (card_type) {
#ifdef USB8897
	case CARD_TYPE_USB8897:
		priv->adapter->card_info = &card_info_usb8897;
		break;
#endif
#ifdef USB8997
	case CARD_TYPE_USB8997:
		priv->adapter->card_info = &card_info_usb8997;
		break;
#endif
#ifdef USB8978
	case CARD_TYPE_USB8978:
		priv->adapter->card_info = &card_info_usb8978;
		break;
#endif
#ifdef USB9098
	case CARD_TYPE_USB9098:
		priv->adapter->card_info = &card_info_usb9098;
		break;
	case CARD_TYPE_PCIEUSB9098:
		priv->adapter->card_info = &card_info_pcieusb9098;
		break;
#endif
	case CARD_TYPE_USB9097:
		priv->adapter->card_info = &card_info_usb9097;
		break;
	case CARD_TYPE_PCIEUSB9097:
		priv->adapter->card_info = &card_info_pcieusb9097;
		break;
#ifdef USBIW610
	case CARD_TYPE_USBIW610:
		priv->adapter->card_info = &card_info_usbiw610;
		break;
#endif
#ifdef USBIW624
	case CARD_TYPE_USBIW624:
		priv->adapter->card_info = &card_info_usbiw624;
		break;
#endif
	default:
		PRINTM(ERROR, "BT can't get right card type \n");
		ret = BT_STATUS_FAILURE;
		break;
	}

	LEAVE();
	return ret;
}

static int
inc_tx(bt_private *priv)
{
	struct usb_card_rec *card = (struct usb_card_rec *)priv->bt_dev.card;
	unsigned long flags;

	spin_lock_irqsave(&card->txlock, flags);
	card->tx_in_flight++;
	spin_unlock_irqrestore(&card->txlock, flags);

	return 0;
}

static void
usb_stop_rx_traffic(struct usb_card_rec *card)
{
	usb_kill_anchored_urbs(&card->intr_anchor);
	usb_kill_anchored_urbs(&card->bulk_anchor);
	usb_kill_anchored_urbs(&card->isoc_anchor);
}

/**
 *  @brief  This function downloads data blocks to device (Sync URB completion)
 *
 *  @param handle   Pointer to bt_private structure
 *  @param pmbuf    Pointer to bt_usb_buffer structure
 *  @param ep       Endpoint to send
 *  @param timeout  Timeout value in milliseconds (if 0 the wait is forever)
 *
 *  @return         BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
static int
usb_write_data_sync(bt_private *priv, bt_usb_buffer *pbuf, u8 ep, u32 timeout)
{
	struct usb_card_rec *cardp = (struct usb_card_rec *)priv->bt_dev.card;
	u8 *data = (u8 *)(pbuf->pbuf + pbuf->data_offset);
	u32 length = pbuf->data_len;
	int actual_length;
	int ret = BT_STATUS_SUCCESS;

	ENTER();
	if (ep == BT_USB_EP_CMD_EVENT) {

		if (length % cardp->bulk_out_maxpktsize == 0)
			length++;

		/* Send the data block */
		ret = usb_bulk_msg(cardp->udev,
				   usb_sndbulkpipe(cardp->udev, ep),
				   data, length, &actual_length, timeout);
		if (ret < 0) {
			PRINTM(ERROR, "usb_blk_msg for send failed, ret %d\n",
			       ret);
			ret = BT_STATUS_FAILURE;
		}
		pbuf->data_len = actual_length;
	} else {

		PRINTM(ERROR, "Currently usb_write_data_sync() "
		       "only handles BT ACL Endpoint\n");
	}

	LEAVE();
	return ret;

}

/**
 *  @brief  This function read data blocks from device (Sync URB completion)
 *
 *  @param handle   Pointer to bt_private structure
 *  @param pbuf    Pointer to bt_usb_buffer structure
 *  @param ep       Endpoint to receive
 *  @param timeout  Timeout value in milliseconds (if 0 the wait is forever)
 *
 *  @return         BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
static int
usb_read_data_sync(bt_private *priv, bt_usb_buffer *pbuf, u8 ep, u32 timeout)
{
	struct usb_card_rec *cardp = (struct usb_card_rec *)priv->bt_dev.card;
	u8 *data = (u8 *)(pbuf->pbuf + pbuf->data_offset);
	u32 buf_len = pbuf->data_len;
	int actual_length;
	int ret = BT_STATUS_SUCCESS;
	ENTER();

	if (ep == BT_USB_EP_CMD_EVENT) {

		/* Receive the data response */
		ret = usb_bulk_msg(cardp->udev,
				   usb_rcvbulkpipe(cardp->udev, ep),
				   data, buf_len, &actual_length, timeout);
		if (ret < 0) {
			PRINTM(ERROR, "usb_bulk_msg failed: %d\n", ret);
			ret = BT_STATUS_FAILURE;
		}
		pbuf->data_len = actual_length;
	} else {

		PRINTM(ERROR, "Currently usb_read_data_sync() "
		       "only handles BT ACL Endpoint\n");
	}

	LEAVE();
	return ret;
}

/** Callback function for Control, Bulk URBs */
static void
usb_tx_complete(struct urb *urb)
{
	bt_private *priv = (bt_private *)urb->context;
	struct m_dev *m_dev = NULL;
	struct usb_card_rec *card = (struct usb_card_rec *)priv->bt_dev.card;

	PRINTM(INFO, "Tx complete: %p urb status %d count %d\n",
	       urb, urb->status, urb->actual_length);

	if (urb->pipe == usb_sndctrlpipe(card->udev, BT_USB_EP_CMD))
		PRINTM(INFO, "Tx complete: control endpoint\n");
	else if (urb->pipe == usb_sndbulkpipe(card->udev,
					      card->bulk_tx_ep->
					      bEndpointAddress))
		PRINTM(INFO, "Tx complete: bulk endpoint\n");
	else if (urb->pipe == usb_sndbulkpipe(card->udev,
					      card->bulk_cmd_ep->
					      bEndpointAddress))
		PRINTM(INFO, "Tx complete: cmd bulk endpoint\n");

	if (urb->status)
		PRINTM(ERROR, "Tx Urb failed: (%d)\n", urb->status);

	m_dev = &(priv->bt_dev.m_dev[BT_SEQ]);
	bt_interrupt(m_dev);

	spin_lock(&card->txlock);
	card->tx_in_flight--;
	spin_unlock(&card->txlock);

	kfree(urb->setup_packet);
	kfree(urb->transfer_buffer);
	return;
}

/** Callback function for  Isoc URBs */
static void
usb_isoc_tx_complete(struct urb *urb)
{

	PRINTM(INFO, "Tx Isoc complete: %p urb status %d count %d\n",
	       urb, urb->status, urb->actual_length);

	if (urb->status)
		PRINTM(ERROR, "Tx Urb failed: (%d)\n", urb->status);

	kfree(urb->setup_packet);
	kfree(urb->transfer_buffer);
	return;
}

static int
usb_card_to_host(bt_private *priv, u32 pkt_type, u8 *rx_buf, u32 rx_len)
{
	int ret = BT_STATUS_SUCCESS;
	struct mbt_dev *mbt_dev = NULL;
	struct m_dev *mdev_debug = &(priv->bt_dev.m_dev[DEBUG_SEQ]);
	struct debug_dev *debug_dev =
		(struct debug_dev *)priv->bt_dev.m_dev[DEBUG_SEQ].dev_pointer;
	struct usb_card_rec *card = (struct usb_card_rec *)priv->bt_dev.card;
	struct sk_buff *skb = NULL;
	u8 *payload = NULL;
	int buf_len = 0;

	ENTER();

	if (!card) {
		PRINTM(ERROR, "BT: card is NULL!\n");
		ret = BT_STATUS_FAILURE;
		goto exit;
	}
	mbt_dev = (struct mbt_dev *)priv->bt_dev.m_dev[BT_SEQ].dev_pointer;
	if (pkt_type < HCI_ACLDATA_PKT || pkt_type > HCI_EVENT_PKT) {
		ret = BT_STATUS_FAILURE;
		goto exit;
	}
	PRINTM(DATA, "BT: USB Rd %s: len=%d type=%d\n", mbt_dev->name, rx_len,
	       pkt_type);
	DBG_HEXDUMP(DAT_D, "BT: USB Rd", rx_buf, rx_len);
	while (rx_len) {
		/* Check Rx length */
		switch (pkt_type) {
		case HCI_EVENT_PKT:
			if (rx_len >= HCI_EVENT_HDR_SIZE) {
				struct hci_event_hdr *h =
					(struct hci_event_hdr *)rx_buf;
				buf_len = HCI_EVENT_HDR_SIZE + h->plen;
			} else
				ret = BT_STATUS_FAILURE;
			break;
		case HCI_ACLDATA_PKT:
			if (rx_len >= HCI_ACL_HDR_SIZE) {
				struct hci_acl_hdr *h =
					(struct hci_acl_hdr *)rx_buf;
				buf_len =
					HCI_ACL_HDR_SIZE +
					__le16_to_cpu(h->dlen);
			} else
				ret = BT_STATUS_FAILURE;
			break;

		case HCI_SCODATA_PKT:
			if (rx_len >= HCI_SCO_HDR_SIZE) {
				struct hci_sco_hdr *h =
					(struct hci_sco_hdr *)rx_buf;
				buf_len = HCI_SCO_HDR_SIZE + h->dlen;
			} else
				ret = BT_STATUS_FAILURE;
			break;
		}

		if (rx_len < buf_len)
			ret = BT_STATUS_FAILURE;

		if (ret == BT_STATUS_FAILURE) {
			PRINTM(ERROR, "BT: Invalid Length =%d!\n", rx_len);
			goto exit;
		}

		/* Allocate skb */
		skb = bt_skb_alloc(buf_len, GFP_ATOMIC);
		if (!skb) {
			PRINTM(WARN, "BT: Failed to allocate skb\n");
			ret = BT_STATUS_FAILURE;
			goto exit;
		}
		payload = skb->data;
		memcpy(payload, rx_buf, buf_len);

		/* Forward the packet up */
		switch (pkt_type) {
		case HCI_ACLDATA_PKT:
			bt_cb(skb)->pkt_type = pkt_type;
			skb_put(skb, buf_len);
			if (*(u16 *) skb->data == 0xffff) {
				bt_store_firmware_dump(priv, skb->data,
						       skb->len);
				dev_kfree_skb_any(skb);
				break;
			}
			bt_recv_frame(priv, skb);
			break;
		case HCI_SCODATA_PKT:
			bt_cb(skb)->pkt_type = pkt_type;
			skb_put(skb, buf_len);
			bt_recv_frame(priv, skb);
			break;
		case HCI_EVENT_PKT:
			/** add EVT Demux */
			bt_cb(skb)->pkt_type = pkt_type;
			skb_put(skb, buf_len);
			if (skb->data[0] != 0xFF) {
				/* NOTE: Unlike other interfaces, for USB
				   event_type= * MRVL_VENDOR_PKT comes as a
				   subpart of HCI_EVENT_PKT * data[0]=0xFF.
				   Hence it needs to be handled separately * by
				   bt_process_event() first. */
				if (BT_STATUS_SUCCESS ==
				    check_evtpkt(priv, skb))
					break;
			}
			switch (skb->data[0]) {
			case 0x0E:
				/** cmd complete */
				if (priv->debug_device_pending) {
					if (priv->debug_ocf_ogf[0] ==
					    skb->data[3] &&
					    priv->debug_ocf_ogf[1] ==
					    skb->data[4]) {
						priv->debug_device_pending = 0;
						priv->debug_ocf_ogf[0] = 0;
						priv->debug_ocf_ogf[1] = 0;
					/** debug cmd complete */
						if (debug_dev) {
							skb->dev =
								(void *)
								mdev_debug;
							mdev_recv_frame(skb);
							mdev_debug->stat.
								byte_rx +=
								buf_len;
						}
						break;
					}
				}
				bt_recv_frame(priv, skb);
				break;
			case 0x0F:
				/** cmd status */
				bt_recv_frame(priv, skb);
				break;
			case 0xFF:
				/** Vendor specific pkt */
				if (BT_STATUS_SUCCESS !=
				    bt_process_event(priv, skb))
					bt_recv_frame(priv, skb);
				break;
			default:
				bt_recv_frame(priv, skb);
				break;
			}
			break;
		default:
			break;
		}
		rx_len -= buf_len;
		rx_buf += buf_len;
	}

exit:
	LEAVE();
	return ret;
}

/** reassemble event data packets */
static int
btusb_recv_intr(bt_private *priv, void *buffer, int count)
{
	struct sk_buff *skb = NULL;
	struct m_dev *mbt_dev = &priv->bt_dev.m_dev[BT_SEQ];
	int err = 0;

	if (!mbt_dev->dev_pointer) {
		PRINTM(ERROR, "Drop intr pkt before device ready\n");
		DBG_HEXDUMP(DAT_D, "Intr Rx: ", buffer, count);
		return err;
	}

	spin_lock(&mbt_dev->rxlock);
	skb = mbt_dev->evt_skb;

	while (count) {
		int len;

		if (!skb) {
			skb = bt_skb_alloc(HCI_MAX_EVENT_SIZE, GFP_ATOMIC);
			if (!skb) {
				err = -ENOMEM;
				break;
			}

			bt_cb(skb)->pkt_type = HCI_EVENT_PKT;
			bt_cb(skb)->expect = HCI_EVENT_HDR_SIZE;
		}

		len = min_t(uint, bt_cb(skb)->expect, count);
		memcpy(skb_put(skb, len), buffer, len);

		count -= len;
		buffer += len;
		bt_cb(skb)->expect -= len;

		if (skb->len == HCI_EVENT_HDR_SIZE) {
			/* Complete event header */
			bt_cb(skb)->expect = hci_event_hdr (skb)->plen;

			if (skb_tailroom(skb) < bt_cb(skb)->expect) {
				PRINTM(ERROR,
				       "Event data exceeded skb tail room\n");
				kfree_skb(skb);
				skb = NULL;
				err = -EILSEQ;
				break;
			}
		}

		if (bt_cb(skb)->expect == 0) {
			/* Complete frame */
			usb_card_to_host(priv, HCI_EVENT_PKT, skb->data,
					 skb->len);
			kfree_skb(skb);
			skb = NULL;
		}
	}

	mbt_dev->evt_skb = skb;
	spin_unlock(&mbt_dev->rxlock);

	return err;
}

/** reassemble ACL data packets */
static int
btusb_recv_bulk(bt_private *priv, void *buffer, int count)
{
	struct sk_buff *skb = NULL;
	struct m_dev *mbt_dev = &priv->bt_dev.m_dev[BT_SEQ];
	int err = 0;

	if (!mbt_dev->dev_pointer) {
		PRINTM(ERROR, "Drop bulk pkt before device ready\n");
		DBG_HEXDUMP(DAT_D, "bulk rx:", buffer, count);
		return err;
	}

	spin_lock(&mbt_dev->rxlock);
	skb = mbt_dev->acl_skb;

	while (count) {
		int len;

		if (!skb) {
			skb = bt_skb_alloc(HCI_MAX_FRAME_SIZE, GFP_ATOMIC);
			if (!skb) {
				err = -ENOMEM;
				break;
			}

			bt_cb(skb)->pkt_type = HCI_ACLDATA_PKT;
			bt_cb(skb)->expect = HCI_ACL_HDR_SIZE;
		}

		len = min_t(uint, bt_cb(skb)->expect, count);
		memcpy(skb_put(skb, len), buffer, len);

		count -= len;
		buffer += len;
		bt_cb(skb)->expect -= len;

		if (skb->len == HCI_ACL_HDR_SIZE) {
			__le16 dlen = hci_acl_hdr(skb)->dlen;

			/* Complete ACL header */
			bt_cb(skb)->expect = __le16_to_cpu(dlen);

			if (skb_tailroom(skb) < bt_cb(skb)->expect) {
				PRINTM(ERROR,
				       "ACL data exceeded skb tail room\n");
				kfree_skb(skb);
				skb = NULL;
				err = -EILSEQ;
				break;
			}
		}

		if (bt_cb(skb)->expect == 0) {
			/* Complete frame */
			usb_card_to_host(priv, HCI_ACLDATA_PKT, skb->data,
					 skb->len);
			kfree_skb(skb);
			skb = NULL;
		}
	}

	mbt_dev->acl_skb = skb;
	spin_unlock(&mbt_dev->rxlock);

	return err;
}

/** reassemble SCO data packets */
static int
btusb_recv_isoc(bt_private *priv, void *buffer, int count)
{
	struct sk_buff *skb = NULL;
	struct m_dev *mbt_dev = &priv->bt_dev.m_dev[BT_SEQ];
	int err = 0;

	if (!mbt_dev->dev_pointer) {
		PRINTM(ERROR, "Drop isoc pkt before device ready\n");
		DBG_HEXDUMP(DAT_D, "isoc rx:", buffer, count);
		return err;
	}

	spin_lock(&mbt_dev->rxlock);
	skb = mbt_dev->sco_skb;
	while (count) {
		int len;
		if (!skb) {
			skb = bt_skb_alloc(HCI_MAX_SCO_SIZE, GFP_ATOMIC);
			if (!skb) {
				PRINTM(ERROR, "failed to alloc sco skb\n");
				err = -ENOMEM;
				break;
			}
			bt_cb(skb)->pkt_type = HCI_SCODATA_PKT;
			bt_cb(skb)->expect = HCI_SCO_HDR_SIZE;
		}

		len = min_t(uint, bt_cb(skb)->expect, count);
		memcpy(skb_put(skb, len), buffer, len);

		count -= len;
		buffer += len;
		bt_cb(skb)->expect -= len;

		if (skb->len == HCI_SCO_HDR_SIZE) {
			/* Complete SCO header */
			bt_cb(skb)->expect = hci_sco_hdr(skb)->dlen;
			if (skb_tailroom(skb) < bt_cb(skb)->expect) {
				PRINTM(ERROR,
				       "sco data exceeded skb tail room\n");
				kfree_skb(skb);
				skb = NULL;
				err = -EILSEQ;
				break;
			}
		}

		if (bt_cb(skb)->expect == 0) {
			/* Complete frame */
			usb_card_to_host(priv, HCI_SCODATA_PKT, skb->data,
					 skb->len);
			kfree_skb(skb);
			skb = NULL;
		}
	}

	mbt_dev->sco_skb = skb;
	spin_unlock(&mbt_dev->rxlock);
	return err;
}

/** Callback function for Interrupt IN URB (Event) */
static void
usb_intr_rx_complete(struct urb *urb)
{
	int err = 0;
	bt_private *priv = (bt_private *)urb->context;
	struct usb_card_rec *card = (struct usb_card_rec *)priv->bt_dev.card;

	PRINTM(INFO, "Intr Rx complete: urb %p status %d count %d\n",
	       urb, urb->status, urb->actual_length);

	if (urb->status == 0) {

		// DBG_HEXDUMP(DAT_D, "Intr Rx: ", urb->transfer_buffer,
		// urb->actual_length);
		err = btusb_recv_intr(priv, urb->transfer_buffer,
				      urb->actual_length);
		if (err < 0) {
			PRINTM(ERROR, "Corrupted event packet: %d\n", err);
		}
	} else if (urb->status == -ENOENT) {
		/* Avoid suspend failed when usb_kill_urb */
		return;
	}

	if (!test_bit(BT_USB_INTR_RUNNING, &card->flags))
		return;

	usb_mark_last_busy(card->udev);
	usb_anchor_urb(urb, &card->intr_anchor);

	/* Resubmit the URB */
	err = usb_submit_urb(urb, GFP_ATOMIC);
	if (err < 0) {
		PRINTM(ERROR, "Intr Rx urb %p failed to resubmit (%d)\n",
		       urb, err);
		usb_unanchor_urb(urb);
	}
	return;
}

/** Callback function for Bulk IN URB (ACL Data) */
static void
usb_bulk_rx_complete(struct urb *urb)
{
	int err = 0;
	bt_private *priv = (bt_private *)urb->context;
	struct usb_card_rec *card = (struct usb_card_rec *)priv->bt_dev.card;

	PRINTM(INFO, "Bulk RX complete: urb %p status %d count %d\n",
	       urb, urb->status, urb->actual_length);

	if (urb->status == 0) {
		err = btusb_recv_bulk(priv, urb->transfer_buffer,
				      urb->actual_length);
		if (err < 0) {
			PRINTM(ERROR, "Corrupted ACL packet: %d\n", err);
		}
	} else if (urb->status == -ENOENT) {
		/* Avoid suspend failed when usb_kill_urb */
		return;
	}

	if (!test_bit(BT_USB_BULK_RUNNING, &card->flags))
		return;

	usb_anchor_urb(urb, &card->bulk_anchor);
	usb_mark_last_busy(card->udev);

	err = usb_submit_urb(urb, GFP_ATOMIC);
	if (err < 0) {
		PRINTM(ERROR, "urb %p failed to resubmit (%d)\n", urb, err);
		usb_unanchor_urb(urb);
	}
	return;
}

/**
 *  @brief  This function submits bulk URB (Async URB completion)
*/
static int
usb_submit_bt_bulk_urb(bt_private *priv, gfp_t mem_flags)
{
	struct usb_card_rec *card = (struct usb_card_rec *)priv->bt_dev.card;
	struct urb *urb;
	int err, size = ALLOC_USB_BUF_SIZE;
	unsigned int pipe;
	unsigned char *buf;

	ENTER();

	if (!card->bulk_rx_ep)
		return -ENODEV;

	urb = usb_alloc_urb(0, mem_flags);
	if (!urb)
		return -ENOMEM;

	buf = kmalloc(size, mem_flags);
	if (!buf) {
		usb_free_urb(urb);
		return -ENOMEM;
	}
	pipe = usb_rcvbulkpipe(card->udev, card->bulk_rx_ep->bEndpointAddress);

	usb_fill_bulk_urb(urb, card->udev, pipe,
			  buf, size, usb_bulk_rx_complete, priv);

	urb->transfer_flags |= URB_FREE_BUFFER;

	usb_mark_last_busy(card->udev);
	usb_anchor_urb(urb, &card->bulk_anchor);

	err = usb_submit_urb(urb, mem_flags);
	if (err < 0) {
		PRINTM(ERROR, "bulk urb %p submission failed (%d)", urb, err);
		usb_unanchor_urb(urb);
	}

	usb_free_urb(urb);

	LEAVE();
	return err;
}

/**
 *  @brief  This function submits Int URB (Async URB completion)
*/
static int
usb_submit_bt_intr_urb(bt_private *priv, gfp_t mem_flags)
{
	struct usb_card_rec *card = (struct usb_card_rec *)priv->bt_dev.card;
	struct urb *urb;
	int err, size = HCI_MAX_EVENT_SIZE;
	unsigned char *buf;
	unsigned int pipe;

	ENTER();

	if (!card->intr_ep)
		return -ENODEV;

	urb = usb_alloc_urb(0, mem_flags);
	if (!urb)
		return -ENOMEM;

	buf = kmalloc(size, mem_flags);
	if (!buf) {
		usb_free_urb(urb);
		return -ENOMEM;
	}

	pipe = usb_rcvintpipe(card->udev, card->intr_ep->bEndpointAddress);

	usb_fill_int_urb(urb, card->udev, pipe, buf, size,
			 usb_intr_rx_complete, priv, card->intr_ep->bInterval);
	urb->transfer_flags |= URB_FREE_BUFFER;

	usb_anchor_urb(urb, &card->intr_anchor);

	err = usb_submit_urb(urb, GFP_ATOMIC);
	if (err < 0) {
		PRINTM(ERROR, "intr urb %p submission failed (%d)", urb, err);
		usb_unanchor_urb(urb);
	}

	usb_free_urb(urb);

	LEAVE();
	return err;
}

/**
 *  @brief This function reads one block of firmware data
 *
 *  @param pdriver_handle Pointer to the driver context
 *  @param offset       Offset from where the data will be copied
 *  @param len          Length to be copied
 *  @param pbuf         Buffer where the data will be copied
 *
 *  @return             BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
static int
usb_get_fw_data(bt_private *priv, u32 offset, u32 len, u8 *pbuf)
{
	if (!pbuf || !len)
		return BT_STATUS_FAILURE;

	if (offset + len > priv->firmware->size)
		return BT_STATUS_FAILURE;

	memcpy(pbuf, priv->firmware->data + offset, len);

	return BT_STATUS_SUCCESS;
}

/**
 *  @brief  This function checks chip revision id
 *
 *  @param priv       A pointer to bt_private
 *  @param rev_id         A pointer to revision_id
 *
 *  @return             BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
static int
usb_check_chip_revision(bt_private *priv, u32 *rev_id)
{
	int ret = BT_STATUS_SUCCESS;
	u8 *recv_buff = NULL;
	u8 *tx_buff = NULL;
	bt_usb_buffer mbuf;
	FWSyncHeader header;

	ENTER();

	tx_buff = kmalloc(FW_DNLD_TX_BUF_SIZE, GFP_ATOMIC | GFP_DMA);
	if (!tx_buff) {
		PRINTM(ERROR, "Could not allocate buffer for tx_buff\n");
		goto exit;
	}
	recv_buff = kmalloc(FW_DNLD_RX_BUF_SIZE, GFP_ATOMIC | GFP_DMA);
	if (!recv_buff) {
		PRINTM(ERROR, "Could not allocate buffer for recv_buff\n");
		goto exit;
	}
	memset(&header, 0, sizeof(header));
	memset(&mbuf, 0, sizeof(bt_usb_buffer));
	memset(tx_buff, 0, sizeof(FWHeader));
	mbuf.pbuf = tx_buff;
	mbuf.data_len = sizeof(FWHeader);
	ret = usb_write_data_sync(priv, &mbuf, BT_USB_EP_CMD_EVENT,
				  BT_USB_BULK_MSG_TIMEOUT);
	if (ret != BT_STATUS_SUCCESS) {
		PRINTM(ERROR, "fw_dnld: wr_data failed (%d)\n", ret);
		goto exit;
	}
	memset(&mbuf, 0, sizeof(bt_usb_buffer));
	mbuf.pbuf = recv_buff;
	mbuf.data_len = FW_DNLD_RX_BUF_SIZE;
	ret = usb_read_data_sync(priv, &mbuf, BT_USB_EP_CMD_EVENT,
				 BT_USB_BULK_MSG_TIMEOUT);
	if (ret != BT_STATUS_SUCCESS) {
		PRINTM(ERROR, "fw_dnld: read_data failed (%d)\n", ret);
		goto exit;
	}
	memcpy(&header, recv_buff, sizeof(FWSyncHeader));
	*rev_id = header.chip_rev & 0x000000ff;
exit:
	if (recv_buff)
		kfree(recv_buff);
	if (tx_buff)
		kfree(tx_buff);

	LEAVE();
	return ret;
}

/**
 *  @brief  This function downloads FW blocks to device
 *
 *  @param priv       A pointer to bt_private
 *  @param pmfw         A pointer to firmware image
 *
 *  @return             BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
static int
usb_prog_fw_w_helper(bt_private *priv, pbt_usb_fw_image pmfw)
{
	int ret = BT_STATUS_SUCCESS;
	u8 *firmware = pmfw->pfw_buf, *RecvBuff;
	u32 retries = MAX_FW_RETRY, DataLength;
	u32 FWSeqNum = 0, TotalBytes = 0, DnldCmd = 0;
	FWData *fwdata = NULL;
	FWSyncHeader SyncFWHeader;
	u8 check_winner = 1;

	ENTER();

	if (!firmware) {
		PRINTM(MSG, "No firmware image found! Terminating download\n");
		ret = BT_STATUS_FAILURE;
		goto fw_exit;
	}

	/* Allocate memory for transmit */
	fwdata = kmalloc(FW_DNLD_TX_BUF_SIZE, GFP_ATOMIC | GFP_DMA);
	if (!fwdata) {
		PRINTM(ERROR, "Could not allocate buffer for FW download\n");
		goto fw_exit;
	}

	/* Allocate memory for receive */
	RecvBuff = kmalloc(FW_DNLD_TX_BUF_SIZE, GFP_ATOMIC | GFP_DMA);
	if (!RecvBuff) {
		PRINTM(ERROR, "Couldn't allocate buffer for FW DW response\n");
		goto cleanup;
	}

	do {
		/* Send pseudo data to check winner status first */
		if (check_winner) {
			memset(&fwdata->fw_header, 0, sizeof(FWHeader));
			DataLength = 0;
		} else {
			/* Copy the header of the fw data to get the len */
			if (firmware)
				memcpy(&fwdata->fw_header,
				       &firmware[TotalBytes], sizeof(FWHeader));
			else
				usb_get_fw_data(priv, TotalBytes,
						sizeof(FWHeader),
						(u8 *)&fwdata->fw_header);

			DataLength = fwdata->fw_header.data_length;
			DnldCmd = fwdata->fw_header.dnld_cmd;
			TotalBytes += sizeof(FWHeader);

			/** CMD 4/6/7/10 don't have data_length filed */
			if (DnldCmd == FW_CMD_4 || DnldCmd == FW_CMD_6 ||
			    DnldCmd == FW_CMD_7 || DnldCmd == FW_CMD_10)
				DataLength = 0;
			/* Copy the firmware data */
			if (firmware)
				if (DataLength > 0)
					memcpy(fwdata->data,
					       &firmware[TotalBytes],
					       DataLength);
				else
					PRINTM(ERROR, "Check on length "
					       "not non-zero value\n");
			else
				usb_get_fw_data(priv, TotalBytes, DataLength,
						(u8 *)fwdata->data);

			fwdata->seq_num = FWSeqNum;
			TotalBytes += DataLength;
		}

		/* If the send/receive fails or CRC occurs then retry */
		while (retries) {
			bt_usb_buffer mbuf;
			int length = FW_DATA_XMIT_SIZE;
			retries--;

			memset(&mbuf, 0, sizeof(bt_usb_buffer));
			mbuf.pbuf = (u8 *)fwdata;
			mbuf.data_len = length;

			/* Send the firmware block */
			ret = usb_write_data_sync(priv,
						  &mbuf, BT_USB_EP_CMD_EVENT,
						  BT_USB_BULK_MSG_TIMEOUT);
			if (ret != BT_STATUS_SUCCESS) {
				PRINTM(ERROR, "fw_dnld: wr_data failed (%d)\n",
				       ret);
				continue;
			}

			memset(&mbuf, 0, sizeof(bt_usb_buffer));
			mbuf.pbuf = RecvBuff;
			mbuf.data_len = FW_DNLD_RX_BUF_SIZE;

			/* Receive the firmware block response */
			ret = usb_read_data_sync(priv,
						 &mbuf, BT_USB_EP_CMD_EVENT,
						 BT_USB_BULK_MSG_TIMEOUT);
			if (ret != BT_STATUS_SUCCESS) {
				PRINTM(ERROR, "fw_dnld: rd_data failed, (%d)\n",
				       ret);
				continue;
			}

			memcpy(&SyncFWHeader, RecvBuff, sizeof(FWSyncHeader));

			/* Check the first FW block resp for highest bit set */
			if (check_winner) {
				if (SyncFWHeader.cmd & 0x80000000) {
					PRINTM(MSG, "USB is not the winner"
					       " 0x%x, returning success\n",
					       SyncFWHeader.cmd);
					ret = BT_STATUS_SUCCESS;
					goto cleanup;
				}
				PRINTM(INFO, "USB is the winner, "
				       "start to download FW\n");
				check_winner = 0;
				break;
			}

			/* Check the firmware block response for CRC errors */
			if (SyncFWHeader.cmd) {
				{
					PRINTM(ERROR,
					       "FW rcvd Blk with CRC err 0x%x\n",
					       SyncFWHeader.cmd);
					ret = BT_STATUS_FAILURE;
					continue;
				}
			}

			retries = MAX_FW_RETRY;
			break;
		}

		FWSeqNum++;
		PRINTM(INFO, ".\n");

		/* Add FW ending check for secure download */
		if (((DnldCmd == FW_CMD_21) && (DataLength == 0)) ||
		    (TotalBytes >= pmfw->fw_len))
			break;

	} while ((DnldCmd != FW_HAS_LAST_BLOCK) && retries);

cleanup:
	PRINTM(MSG, "fw_dnld: %d bytes downloaded\n", TotalBytes);

	if (RecvBuff)
		kfree(RecvBuff);
	if (fwdata)
		kfree(fwdata);
	if (retries)
		ret = BT_STATUS_SUCCESS;

fw_exit:
	LEAVE();
	return ret;
}

/**
 * @brief Download and Initialize firmware DPC
 *
 * @param handle    A pointer to moal_handle structure
 *
 * @return        BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
static int
usb_init_fw_dpc(bt_private *priv)
{
	int ret = BT_STATUS_SUCCESS;
	bt_usb_fw_image fw;
	struct usb_card_rec *card = (struct usb_card_rec *)priv->bt_dev.card;

	ENTER();

	if (priv->firmware) {
		memset(&fw, 0, sizeof(bt_usb_fw_image));
		fw.pfw_buf = (u8 *)priv->firmware->data;
		fw.fw_len = priv->firmware->size;
		ret = usb_prog_fw_w_helper(priv, &fw);
		if (ret == BT_STATUS_FAILURE) {
			PRINTM(ERROR, "BT: Download FW with nowwait: %d\n",
			       bt_extflg_isset(priv, EXT_BT_REQ_FW_NOWAIT));
			goto done;
		}
		if (card->boot_state == USB_FW_DNLD) {
#ifdef USB8897
			if (IS_USB8897(priv->adapter->card_type)) {
				struct usb_device *udev = card->udev;
				int usbRstDev_ret = 0;

				/* Return now */
				PRINTM(MSG, "BT FW is downloaded\n");

				/* Reset USB device to get re-enumeration */
				if (udev) {
#define USB_WAIT_FW_READY  (500)
					mdelay(USB_WAIT_FW_READY);
					usbRstDev_ret = usb_reset_device(udev);
					if ((usbRstDev_ret == 0) ||
					    /* expected since chip
					       re-enumerates */
					    (usbRstDev_ret == -ENODEV) ||
					    /* expected if USB FW detaches
					       first */
					    (usbRstDev_ret == -EINVAL)) {
						PRINTM(MSG,
						       "USB reset successful.\n");
					} else {
						PRINTM(ERROR,
						       "USB reset failed (%d)\n",
						       usbRstDev_ret);
						ret = BT_STATUS_FAILURE;
					}
				} else {
					PRINTM(ERROR, "ERR: No handle to call "
					       "usb_reset_device()!\n");
					ret = BT_STATUS_FAILURE;
				}
			}
#endif
			goto done;
		} else {
			PRINTM(MSG, "WLAN FW is active\n");
		}
	}

	ret = BT_STATUS_SUCCESS;
done:
	LEAVE();
	return ret;
}

/**
 * @brief Request firmware DPC
 *
 * @param handle    A pointer to moal_handle structure
 * @param firmware  A pointer to firmware image
 *
 * @return        BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
static int
usb_request_fw_dpc(const struct firmware *fw_firmware, void *context)
{
	int ret = BT_STATUS_SUCCESS;
	bt_private *priv = (bt_private *)context;
	struct usb_card_rec *card = NULL;
	struct m_dev *m_dev_bt = NULL;
	bt_timeval tstamp;
	int index;

	ENTER();

	m_dev_bt = &priv->bt_dev.m_dev[BT_SEQ];

	if ((priv == NULL) || (priv->adapter == NULL) ||
	    (priv->bt_dev.card == NULL) || (m_dev_bt == NULL)) {
		LEAVE();
		return BT_STATUS_FAILURE;
	}

	card = (struct usb_card_rec *)priv->bt_dev.card;

	if (!fw_firmware) {
		get_monotonic_time(&tstamp);
		if (tstamp.time_sec >
		    (priv->req_fw_time.time_sec + REQUEST_FW_TIMEOUT)) {
			PRINTM(ERROR, "BT: No FW image found. Skipping d/w\n");
			ret = BT_STATUS_FAILURE;
			goto done;
		}
		PRINTM(ERROR, "BT: No FW %s image found! Retrying d/w\n",
		       priv->adapter->params.fw_name);
		/* Wait a second here before calling the callback again */
		os_sched_timeout(1000);
		usb_download_firmware_w_helper(priv);
		LEAVE();
		return ret;
	}
	priv->firmware = fw_firmware;

	if (BT_STATUS_FAILURE == usb_init_fw_dpc(priv)) {
		PRINTM(ERROR,
		       "BT: usb_init_fw_dpc failed "
		       "(download fw with nowait: %d). Terminating d/w\n",
		       bt_extflg_isset(priv, EXT_BT_REQ_FW_NOWAIT));
		ret = BT_STATUS_FAILURE;
		goto done;
	}

	if (fw_firmware) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32)
		if (!bt_extflg_isset(priv, EXT_BT_REQ_FW_NOWAIT))
#endif
			release_firmware(fw_firmware);
	}
	LEAVE();
	return ret;		/* Success Return */

done:
	/* Failure Return, Free all stuff here! */
	if (fw_firmware) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32)
		if (!bt_extflg_isset(priv, EXT_BT_REQ_FW_NOWAIT))
#endif
			release_firmware(fw_firmware);
	}

	/* For synchronous download cleanup will be done in add_card */
	if (!bt_extflg_isset(priv, EXT_BT_REQ_FW_NOWAIT))
		return ret;

	PRINTM(INFO, "unregister device\n");
	sbi_usb_unregister_dev(priv);

	((struct usb_card_rec *)card)->priv = NULL;

	/* Stop the thread servicing the interrupts */
	priv->SurpriseRemoved = TRUE;
	wake_up_interruptible(&priv->MainThread.waitQ);
	while (priv->MainThread.pid)
		os_sched_timeout(1);

	if (m_dev_bt->dev_pointer) {
		if (m_dev_bt->spec_type == IANYWHERE_SPEC)
			free_m_dev(m_dev_bt);
	}

	if (priv->adapter)
		bt_free_adapter(priv);
	for (index = 0; index < MAX_BT_ADAPTER; index++) {
		if (m_priv[index] == priv) {
			m_priv[index] = NULL;
			break;
		}
	}
	bt_priv_put(priv);

	LEAVE();
	return ret;
}

/**
 * @brief request_firmware callback
 *        This function is invoked by request_firmware_nowait system call
 *
 * @param firmware     A pointer to firmware structure
 * @param context      A Pointer to bt_private structure
 * @return             None
 **/
static void
usb_request_fw_callback(const struct firmware *firmware, void *context)
{
	ENTER();
	usb_request_fw_dpc(firmware, context);
	LEAVE();
	return;
}

/**
 *  @brief This function check the chip rev and update the fw name
 *
 *  @param priv           A pointer to bt_private
 *
 *  @return        N/A
 */
static void
usb_get_fw_name(bt_private *priv)
{
	u16 card_type = priv->adapter->card_type;
	u32 revision_id = 0;
	int ret = BT_STATUS_SUCCESS;

	ret = usb_check_chip_revision(priv, &revision_id);
	if (ret != BT_STATUS_SUCCESS) {
		PRINTM(ERROR, "Failed to get chip revision ID\n");
		goto done;
	}
	PRINTM(MSG, "revision=%d\n", revision_id);
#ifdef USB9098
	if (IS_USB9098(card_type)) {
		switch (revision_id) {
		case USB9098_Z1Z2:
			if (card_type == CARD_TYPE_PCIEUSB9098)
				strcpy(priv->adapter->card_info->fw_name,
				       PCIEUSB9098_DEFAULT_FW_NAME);
			else
				strcpy(priv->adapter->card_info->fw_name,
				       USB9098_DEFAULT_FW_NAME);
			strcpy(priv->adapter->card_info->fw_name_bt,
			       USB9098_DEFAULT_BT_FW_NAME);
			break;
		case USB9098_A0:
		case USB9098_A1:
			if (card_type == CARD_TYPE_PCIEUSB9098)
				strcpy(priv->adapter->card_info->fw_name,
				       PCIEUSB9098_V1_FW_NAME);
			else
				strcpy(priv->adapter->card_info->fw_name,
				       USB9098_V1_FW_NAME);
			strcpy(priv->adapter->card_info->fw_name_bt,
			       USB9098_BT_V1_FW_NAME);
			break;
		default:
			break;
		}
	}
#endif
	if (IS_USB9097(card_type)) {
		switch (revision_id) {
		case USB9097_BT_A0:
			if (card_type == CARD_TYPE_PCIEUSB9097)
				strcpy(priv->adapter->card_info->fw_name,
				       PCIEUSB9097_DEFAULT_FW_NAME);
			else
				strcpy(priv->adapter->card_info->fw_name,
				       USB9097_DEFAULT_FW_NAME);
			strcpy(priv->adapter->card_info->fw_name_bt,
			       USB9097_DEFAULT_BT_FW_NAME);
			break;
		case USB9097_BT_B0:
		case USB9097_BT_B1:
			if (card_type == CARD_TYPE_PCIEUSB9097)
				strcpy(priv->adapter->card_info->fw_name,
				       PCIEUSB9097_V1_FW_NAME);
			else
				strcpy(priv->adapter->card_info->fw_name,
				       USB9097_V1_FW_NAME);
			strcpy(priv->adapter->card_info->fw_name_bt,
			       USB9097_BT_V1_FW_NAME);
			break;
		default:
			break;
		}
	}
done:
	return;
}

/**
 *  @brief This function dynamically populates the driver FW name
 *
 *  @param priv           A pointer to bt_private
 *
 *  @return        BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
static int
usb_download_firmware_w_helper(bt_private *priv)
{
	int ret = BT_STATUS_SUCCESS;
	int err;
	char *cur_fw_name = NULL;

	ENTER();

	cur_fw_name = priv->adapter->params.fw_name;
	if (priv->adapter->params.fw_name == NULL) {
		usb_get_fw_name(priv);
		if (bt_extflg_isset(priv, EXT_BT_FW_SERIAL) &&
		    !priv->adapter->params.bt_fw_reload)
			cur_fw_name = priv->adapter->card_info->fw_name;
		else
			cur_fw_name = priv->adapter->card_info->fw_name_bt;
	}

	if (cur_fw_name == NULL) {
		PRINTM(FATAL, "BT: fwname == NULL\n");
		ret = BT_STATUS_FAILURE;
		goto done;
	}
	PRINTM(MSG, "fw_name=%s\n", cur_fw_name);

	if (bt_extflg_isset(priv, EXT_BT_REQ_FW_NOWAIT)) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
		ret = request_firmware_nowait(THIS_MODULE, FW_ACTION_UEVENT,
					      cur_fw_name, priv->hotplug_device,
					      GFP_KERNEL, priv,
					      usb_request_fw_callback);
#else
		ret = request_firmware_nowait(THIS_MODULE, FW_ACTION_HOTPLUG,
					      cur_fw_name, priv->hotplug_device,
					      GFP_KERNEL, priv,
					      usb_request_fw_callback);
#endif
#else
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 13)
		ret = request_firmware_nowait(THIS_MODULE, FW_ACTION_HOTPLUG,
					      cur_fw_name, priv->hotplug_device,
					      priv, usb_request_fw_callback);
#else
		ret = request_firmware_nowait(THIS_MODULE,
					      cur_fw_name, priv->hotplug_device,
					      priv, usb_request_fw_callback);
#endif
#endif
		if (ret < 0)
			PRINTM(FATAL,
			       "BT: request_firmware_nowait() failed, "
			       "error code = %#x\n", ret);
	} else {
		err = request_firmware(&priv->firmware, cur_fw_name,
				       priv->hotplug_device);
		if (err < 0) {
			PRINTM(FATAL,
			       "BT: request_firmware() failed, "
			       "error code = %#x\n", err);
			ret = BT_STATUS_FAILURE;
		} else {
			ret = usb_request_fw_dpc(priv->firmware, priv);
		}
	}

done:
	LEAVE();
	return ret;
}

#ifdef USB_SCO_SUPPORT
/* Based on which Alternate Setting needs to be used, set the Isoc interface */
static int
usb_set_isoc_interface(bt_private *priv, int altsetting)
{
	struct usb_card_rec *card = (struct usb_card_rec *)priv->bt_dev.card;
	struct usb_interface *intf = card->isoc;
	struct usb_endpoint_descriptor *endpoint;
	int i, err;

	ENTER();

	if (!card->isoc) {
		LEAVE();
		return -ENODEV;
	}

	err = usb_set_interface(card->udev, card->isoc_ifnum, altsetting);
	if (err < 0) {
		PRINTM(ERROR, "Setting isoc interface failed (%d)\n", err);
		LEAVE();
		return err;
	}

	card->isoc_altsetting = altsetting;
	card->isoc_tx_ep = NULL;
	card->isoc_rx_ep = NULL;

	for (i = 0; i < intf->cur_altsetting->desc.bNumEndpoints; i++) {
		endpoint = &intf->cur_altsetting->endpoint[i].desc;

		if (!card->isoc_tx_ep && usb_endpoint_is_isoc_out(endpoint)) {
			/* We found a Isoc out sync_data endpoint */
			PRINTM(INFO, "Isoc OUT: max pkt size = %d, addr = %d\n",
			       endpoint->wMaxPacketSize,
			       endpoint->bEndpointAddress);
			card->isoc_tx_ep = endpoint;
			continue;
		}

		if (!card->isoc_rx_ep && usb_endpoint_is_isoc_in(endpoint)) {
			/* We found a Isoc in sync_data endpoint */
			PRINTM(INFO, "Isoc IN: max pkt size = %d, addr = %d\n",
			       endpoint->wMaxPacketSize,
			       endpoint->bEndpointAddress);
			card->isoc_rx_ep = endpoint;
			continue;
		}
	}

	if (!card->isoc_tx_ep || !card->isoc_rx_ep) {
		PRINTM(ERROR, "invalid SCO endpoints");
		LEAVE();
		return -ENODEV;
	}

	LEAVE();
	return 0;
}

/** Callback function for Isoc IN URB (SCO Data) */
static void
usb_isoc_rx_complete(struct urb *urb)
{
	int err = 0, i;
	bt_private *priv = (bt_private *)urb->context;
	struct usb_card_rec *card = (struct usb_card_rec *)priv->bt_dev.card;

	PRINTM(INFO, "Isoc Rx complete: urb %p status %d count %d\n",
	       urb, urb->status, urb->actual_length);

	if (urb->status == 0 && urb->actual_length > 0) {
		for (i = 0; i < urb->number_of_packets; i++) {
			unsigned int offset = urb->iso_frame_desc[i].offset;
			unsigned int length =
				urb->iso_frame_desc[i].actual_length;

			if (urb->iso_frame_desc[i].status)
				continue;
			err = btusb_recv_isoc(priv,
					      urb->transfer_buffer + offset,
					      length);
			if (err < 0) {
				PRINTM(ERROR, "Corrupted SCO packet: %d\n",
				       err);
			}
		}
	} else if (urb->status == -ENOENT) {
		/* Avoid suspend failed when usb_kill_urb */
		return;
	}

	if (!test_bit(BT_USB_ISOC_RUNNING, &card->flags))
		return;

	usb_anchor_urb(urb, &card->isoc_anchor);

	err = usb_submit_urb(urb, GFP_ATOMIC);
	if (err < 0) {
		PRINTM(ERROR, "isoc urb %p failed to resubmit (%d)\n",
		       urb, err);
		usb_unanchor_urb(urb);
	}
	return;
}

/**
 *  @brief  This function submits isoc URB (Async URB completion)
 */
static int
usb_submit_bt_isoc_urb(bt_private *priv, gfp_t mem_flags)
{
	struct usb_card_rec *card = (struct usb_card_rec *)priv->bt_dev.card;
	struct urb *urb;
	int err, size;
	int len;
	int mtu;
	int i, offset = 0;
	unsigned char *buf;
	unsigned int pipe;

	ENTER();

	urb = usb_alloc_urb(BT_USB_MAX_ISOC_FRAMES, GFP_ATOMIC);
	if (!urb)
		return -ENOMEM;

	size = le16_to_cpu(card->isoc_rx_ep->wMaxPacketSize) *
		BT_USB_MAX_ISOC_FRAMES;

	buf = kmalloc(size, mem_flags);
	if (!buf) {
		usb_free_urb(urb);
		return -ENOMEM;
	}
	pipe = usb_rcvisocpipe(card->udev, card->isoc_rx_ep->bEndpointAddress);

	urb->dev = card->udev;
	urb->pipe = pipe;
	urb->context = priv;
	urb->complete = usb_isoc_rx_complete;
	urb->interval = card->isoc_rx_ep->bInterval;

	urb->transfer_flags = URB_FREE_BUFFER | URB_ISO_ASAP;
	urb->transfer_buffer = buf;
	urb->transfer_buffer_length = size;

	len = size;
	mtu = le16_to_cpu(card->isoc_rx_ep->wMaxPacketSize);
	for (i = 0; i < BT_USB_MAX_ISOC_FRAMES && len >= mtu;
	     i++, offset += mtu, len -= mtu) {
		urb->iso_frame_desc[i].offset = offset;
		urb->iso_frame_desc[i].length = mtu;
	}

	if (len && i < BT_USB_MAX_ISOC_FRAMES) {
		urb->iso_frame_desc[i].offset = offset;
		urb->iso_frame_desc[i].length = len;
		i++;
	}

	urb->number_of_packets = i;

	usb_anchor_urb(urb, &card->isoc_anchor);

	err = usb_submit_urb(urb, GFP_ATOMIC);
	if (err < 0) {
		PRINTM(ERROR, "isoc urb %p submission failed (%d)", urb, err);
		usb_unanchor_urb(urb);
	}

	usb_free_urb(urb);

	LEAVE();
	return err;
}

/* TODO: Instead of BlueZ, there is no hook for char dev to notify our driver
 * about SCO connection num's change, so set the isoc interface and submit rx
 * isoc urb immediately when bulk & intr rx urbs are submitted.
 */
static void
usb_set_isoc_if(bt_private *priv)
{
	struct usb_card_rec *card = (struct usb_card_rec *)priv->bt_dev.card;
	int err;

	ENTER();

	if (!test_bit(BT_USB_DID_ISO_RESUME, &card->flags)) {
		err = usb_autopm_get_interface(card->isoc ? card->isoc :
					       card->intf);
		if (err < 0) {

			clear_bit(BT_USB_ISOC_RUNNING, &card->flags);
			usb_kill_anchored_urbs(&card->isoc_anchor);
			LEAVE();
			return;
		}

		set_bit(BT_USB_DID_ISO_RESUME, &card->flags);
	}
	if (card->isoc_altsetting != 2) {
		clear_bit(BT_USB_ISOC_RUNNING, &card->flags);
		usb_kill_anchored_urbs(&card->isoc_anchor);

		if (usb_set_isoc_interface(priv, 2) < 0) {
			LEAVE();
			return;
		}
	}

	if (!test_and_set_bit(BT_USB_ISOC_RUNNING, &card->flags)) {
		if (usb_submit_bt_isoc_urb(priv, GFP_KERNEL) < 0)
			clear_bit(BT_USB_ISOC_RUNNING, &card->flags);
		else
			usb_submit_bt_isoc_urb(priv, GFP_KERNEL);
	}
	card->sco_num = 1;
	LEAVE();
}

static void
usb_unset_isoc_if(bt_private *priv)
{
	struct usb_card_rec *card = (struct usb_card_rec *)priv->bt_dev.card;

	ENTER();

	card->sco_num = 0;
	clear_bit(BT_USB_ISOC_RUNNING, &card->flags);
	usb_kill_anchored_urbs(&card->isoc_anchor);

	usb_set_isoc_interface(priv, 0);
	if (test_and_clear_bit(BT_USB_DID_ISO_RESUME, &card->flags))
		usb_autopm_put_interface(card->isoc ? card->isoc : card->intf);
	LEAVE();
}

static void
usb_isoc_work(struct work_struct *work)
{
	struct usb_card_rec *card =
		container_of(work, struct usb_card_rec, work);

	ENTER();
	usb_set_isoc_if((bt_private *)card->priv);
	LEAVE();
}

#endif /* USB_SCO_SUPPORT */

/**
 *  @brief Sets the configuration values
 *
 *  @param intf		Pointer to usb_interface
 *  @param id		Pointer to usb_device_id
 *
 *  @return	Address of variable usb_cardp, error code otherwise
 */
static int
bt_usb_probe(struct usb_interface *intf, const struct usb_device_id *id)
{
	struct usb_device *udev;
	struct usb_host_interface *iface_desc;
	struct usb_endpoint_descriptor *endpoint;
	int i, ret = 0, intf_num = 0;
	struct usb_card_rec *usb_cardp = NULL;
	bt_private *priv = NULL;

	PRINTM(MSG, "bt_usb_probe: intf %p id %p", intf, id);
	intf_num = intf->cur_altsetting->desc.bInterfaceNumber;

	usb_cardp = kzalloc(sizeof(struct usb_card_rec), GFP_KERNEL);
	if (!usb_cardp)
		return -ENOMEM;

	udev = interface_to_usbdev(intf);

	/* Check probe is for our device */
	for (i = 0; bt_usb_table[i].idVendor; i++) {

		if (udev->descriptor.idVendor == bt_usb_table[i].idVendor &&
		    udev->descriptor.idProduct == bt_usb_table[i].idProduct) {

			PRINTM(MSG, "VID/PID = %X/%X, Boot2 version = %X\n",
			       udev->descriptor.idVendor,
			       udev->descriptor.idProduct,
			       udev->descriptor.bcdDevice);

			/* Update boot state */
			switch (udev->descriptor.idProduct) {
#ifdef USB8997
			case USB8997_PID_1:
				usb_cardp->boot_state = USB_FW_DNLD;
				usb_cardp->revision_id = USB8997_Z;
				break;
			case USB8997V2_PID_1:
				usb_cardp->boot_state = USB_FW_DNLD;
				usb_cardp->revision_id = USB8997_V2;
				break;
			case USB8997_PID_2:
				usb_cardp->boot_state = USB_FW_READY;
				break;
#endif
#ifdef USB8978
			case USB8978_PID_1:
			case USBUSB8978_PID_1_WLAN:
				usb_cardp->boot_state = USB_FW_DNLD;
				break;
			case USB8978_PID_2:
			case USB8978_PID_2_WLAN:
				usb_cardp->boot_state = USB_FW_READY;
				break;
#endif

#ifdef USB8897
			case USB8897_PID_1:
				usb_cardp->boot_state = USB_FW_DNLD;
				break;
			case USB8897_PID_2:
				usb_cardp->boot_state = USB_FW_READY;
				break;
#endif
#ifdef USBIW610
			case USBIW610_PID_1:
				usb_cardp->boot_state = USB_FW_DNLD;
				break;
			case USBIW610_PID_2:
				usb_cardp->boot_state = USB_FW_READY;
				break;
#endif
#ifdef USBIW624
			case USBUSBIW624_PID_1:
				usb_cardp->boot_state = USB_FW_DNLD;
				break;
			case USBUSBIW624_PID_2:
				usb_cardp->boot_state = USB_FW_READY;
				break;
#endif
			case USBUSB9097_PID_1:
			case PCIEUSB9097_PID_1:
				usb_cardp->boot_state = USB_FW_DNLD;
				break;
			case PCIEUSB9097_PID_2:
			case USBUSB9097_PID_2:
				usb_cardp->boot_state = USB_FW_READY;
				break;
#ifdef USB9098
			case USBUSB9098_PID_1:
			case PCIEUSB9098_PID_1:
				usb_cardp->boot_state = USB_FW_DNLD;
				break;
			case PCIEUSB9098_PID_2:
			case USBUSB9098_PID_2:
				usb_cardp->boot_state = USB_FW_READY;
				break;
#endif
			default:
				usb_cardp->boot_state = USB_FW_DNLD;
				break;
			}

			/* Update card type */
			switch (udev->descriptor.idProduct) {
#ifdef USB8997
			case USB8997_PID_1:
			case USB8997V2_PID_1:
			case USB8997_PID_2:
				usb_cardp->card_type = CARD_TYPE_USB8997;
				memcpy(mbt_driver_version, CARD_USB8997,
				       strlen(CARD_USB8997));
				break;
#endif
#ifdef USB8978
			case USB8978_PID_1:
			case USBUSB8978_PID_1_WLAN:
			case USB8978_PID_2:
			case USB8978_PID_2_WLAN:
				usb_cardp->card_type = CARD_TYPE_USB8978;
				memcpy(mbt_driver_version, CARD_USB8978,
				       strlen(CARD_USB8978));
				break;
#endif
#ifdef USB8897
			case USB8897_PID_1:
			case USB8897_PID_2:
				usb_cardp->card_type = CARD_TYPE_USB8897;
				memcpy(mbt_driver_version, CARD_USB8897,
				       strlen(CARD_USB8897));
				break;
#endif
#ifdef USBIW610
			case USBIW610_PID_1:
			case USBIW610_PID_2:
				usb_cardp->card_type = CARD_TYPE_USBIW610;
				memcpy(mbt_driver_version, CARD_USBIW610,
				       strlen(CARD_USBIW610));
				break;
#endif
#ifdef USBIW624
			case USBUSBIW624_PID_1:
			case USBUSBIW624_PID_2:
				usb_cardp->card_type = CARD_TYPE_USBIW624;
				memcpy(mbt_driver_version, CARD_USBIW624,
				       strlen(CARD_USBIW624));
				break;
#endif

			case USBUSB9097_PID_1:
			case USBUSB9097_PID_2:
				usb_cardp->card_type = CARD_TYPE_USB9097;
				memcpy(mbt_driver_version, CARD_USB9097,
				       strlen(CARD_USB9097));
				break;
			case PCIEUSB9097_PID_1:
			case PCIEUSB9097_PID_2:
				usb_cardp->card_type = CARD_TYPE_PCIEUSB9097;
				memcpy(mbt_driver_version, CARD_USB9097,
				       strlen(CARD_USB9097));
				break;
#ifdef USB9098
			case USBUSB9098_PID_1:
			case USBUSB9098_PID_2:
				usb_cardp->card_type = CARD_TYPE_USB9098;
				memcpy(mbt_driver_version, CARD_USB9098,
				       strlen(CARD_USB9098));
				break;
			case PCIEUSB9098_PID_1:
			case PCIEUSB9098_PID_2:
				usb_cardp->card_type = CARD_TYPE_PCIEUSB9098;
				memcpy(mbt_driver_version, CARD_USB9098,
				       strlen(CARD_USB9098));
				break;
#endif
			default:
				PRINTM(ERROR, "Invalid card type detected\n");
				break;
			}
			break;
		}
	}

	if (bt_usb_table[i].idVendor) {

		usb_cardp->udev = udev;
		usb_cardp->intf = intf;
		iface_desc = intf->cur_altsetting;

		PRINTM(INFO, "bcdUSB = 0x%X bDeviceClass = 0x%X"
		       " bDeviceSubClass = 0x%X, bDeviceProtocol = 0x%X\n",
		       udev->descriptor.bcdUSB,
		       udev->descriptor.bDeviceClass,
		       udev->descriptor.bDeviceSubClass,
		       udev->descriptor.bDeviceProtocol);

		/* BT Commands will use USB's control endpoint (Ept-0) */
		PRINTM(INFO, "CTRL IN/OUT: max pkt size = %d, addr = %d\n",
		       udev->descriptor.bMaxPacketSize0, BT_USB_EP_CMD);

		/* Extract Other Endpoints */
		for (i = 0; i < iface_desc->desc.bNumEndpoints; ++i) {
			endpoint = &iface_desc->endpoint[i].desc;
			if ((usb_cardp->boot_state == USB_FW_DNLD) &&
			    (usb_endpoint_is_bulk_in(endpoint)) &&
			    ((endpoint->
			      bEndpointAddress & USB_ENDPOINT_NUMBER_MASK) ==
			     BT_USB_EP_CMD_EVENT)) {
				/* We found a bulk in command/event endpoint */
				PRINTM(INFO,
				       "Bulk IN DNLD: max packet size = %d, address = %d\n",
				       endpoint->wMaxPacketSize,
				       endpoint->bEndpointAddress);
				usb_cardp->rx_cmd_ep =
					(endpoint->
					 bEndpointAddress &
					 USB_ENDPOINT_NUMBER_MASK);
				continue;
			}
			if ((usb_cardp->boot_state == USB_FW_DNLD) &&
			    (usb_endpoint_is_bulk_out(endpoint)) &&
			    ((endpoint->
			      bEndpointAddress & USB_ENDPOINT_NUMBER_MASK) ==
			     BT_USB_EP_CMD_EVENT)) {
				/* We found a bulk out command/event endpoint */
				PRINTM(INFO,
				       "Bulk OUT DNLD: max packet size = %d, address = %d\n",
				       endpoint->wMaxPacketSize,
				       endpoint->bEndpointAddress);
				usb_cardp->tx_cmd_ep =
					endpoint->bEndpointAddress;
				usb_cardp->bulk_out_maxpktsize =
					endpoint->wMaxPacketSize;
				continue;
			}
			if (!usb_cardp->intr_ep &&
			    usb_endpoint_is_int_in(endpoint)) {

				/* We found a interrupt in event endpoint */
				PRINTM(INFO, "INT IN: max pkt size = %d, "
				       "addr = %d\n",
				       endpoint->wMaxPacketSize,
				       endpoint->bEndpointAddress);
				usb_cardp->intr_ep = endpoint;
				continue;
			}

			if (!usb_cardp->bulk_rx_ep &&
			    usb_endpoint_is_bulk_in(endpoint)) {

				/* We found a bulk in data endpoint */
				PRINTM(INFO, "Bulk IN DATA: max pkt size = %d, "
				       "addr = %d\n",
				       endpoint->wMaxPacketSize,
				       endpoint->bEndpointAddress);
				usb_cardp->bulk_rx_ep = endpoint;
				continue;
			}

			if (!usb_cardp->bulk_tx_ep &&
			    usb_endpoint_is_bulk_out(endpoint)) {

				/* We found a bulk out data endpoint */
				PRINTM(INFO,
				       "Bulk OUT DATA: max pkt size = %d, "
				       "addr = %d\n", endpoint->wMaxPacketSize,
				       endpoint->bEndpointAddress);
				usb_cardp->bulk_tx_ep = endpoint;
				continue;
			}

			if (!usb_cardp->bulk_cmd_ep &&
			    usb_endpoint_is_bulk_out(endpoint)) {

				/* We found a bulk out cmd endpoint */
				PRINTM(INFO, "Bulk OUT CMD: max pkt size = %d, "
				       "addr = %d\n",
				       endpoint->wMaxPacketSize,
				       endpoint->bEndpointAddress);
				usb_cardp->bulk_cmd_ep = endpoint;
				continue;
			}
		}

		if ((usb_cardp->boot_state == USB_FW_DNLD) &&
		    (!usb_cardp->rx_cmd_ep || !usb_cardp->tx_cmd_ep)) {
			ret = -ENODEV;
			goto error;
		} else if (usb_cardp->boot_state == USB_FW_READY) {
			if (!usb_cardp->intr_ep || !usb_cardp->bulk_tx_ep ||
			    !usb_cardp->bulk_rx_ep) {
				ret = -ENODEV;
				goto error;
			}
		}

		usb_cardp->cmdreq_type = USB_TYPE_CLASS;

		spin_lock_init(&usb_cardp->txlock);
		spin_lock_init(&usb_cardp->rxlock);

#ifdef USB_SCO_SUPPORT
		INIT_WORK(&usb_cardp->work, usb_isoc_work);
#endif

		init_usb_anchor(&usb_cardp->tx_anchor);
		init_usb_anchor(&usb_cardp->intr_anchor);
		init_usb_anchor(&usb_cardp->bulk_anchor);
		init_usb_anchor(&usb_cardp->isoc_anchor);

		usb_cardp->isoc = usb_ifnum_to_if(udev, intf_num + 1);
		usb_cardp->isoc_ifnum = intf_num + 1;

		if (usb_cardp->isoc) {

			ret = usb_driver_claim_interface(&bt_usb_driver,
							 usb_cardp->isoc,
							 usb_cardp);
			if (ret < 0)
				goto error;
			PRINTM(INFO, "bt_usb_probe: isoc intf %p id %p",
			       usb_cardp->isoc, id);
		}

		usb_set_intfdata(intf, usb_cardp);

		/* At this point bt_add_card() will be called */
		priv = bt_add_card(usb_cardp, &udev->dev, &usb_ops,
				   usb_cardp->card_type);
		usb_cardp->priv = (void *)priv;
		if (!priv) {
			PRINTM(ERROR, "bt_add_card failed\n");
			usb_set_intfdata(intf, NULL);
			goto error;
		}
		usb_get_dev(udev);
		return 0;
	} else {
		PRINTM(INFO, "Discard the Probe request\n");
		PRINTM(INFO, "VID = 0x%X PID = 0x%X\n",
		       udev->descriptor.idVendor, udev->descriptor.idProduct);
	}

error:
	if (ret != (-ENODEV))
		ret = -ENXIO;
	kfree(usb_cardp);
	return ret;
}

/**
 *  @brief Free resource and cleanup
 *
 *  @param intf		Pointer to usb_interface
 *
 *  @return		N/A
 */
static void
bt_usb_disconnect(struct usb_interface *intf)
{
	struct usb_card_rec *cardp = usb_get_intfdata(intf);

	PRINTM(MSG, "bt_usb_disconnect: intf %p, cardp %p\n", intf, cardp);

	if (!cardp || !cardp->priv) {
		PRINTM(INFO, "Card is not valid\n");
		return;
	}

	PRINTM(INFO, "Call remove card\n");
	bt_remove_card(cardp->priv);

	PRINTM(INFO, "Call USB cleanup routines\n");
	usb_set_intfdata(cardp->intf, NULL);
	usb_put_dev(interface_to_usbdev(intf));
	if (cardp->isoc)
		usb_set_intfdata(cardp->isoc, NULL);

	if (intf == cardp->isoc)
		usb_driver_release_interface(&bt_usb_driver, cardp->intf);
	else if (cardp->isoc)
		usb_driver_release_interface(&bt_usb_driver, cardp->isoc);

	kfree(cardp);
	return;
}

#ifdef CONFIG_PM
/**
 *  @brief Handle suspend
 *
 *  @param intf		Pointer to usb_interface
 *  @param message	Pointer to pm_message_t structure
 *
 *  @return		BT_STATUS_SUCCESS
 */
static int
bt_usb_suspend(struct usb_interface *intf, pm_message_t message)
{
	struct usb_card_rec *cardp = usb_get_intfdata(intf);
	bt_private *priv = NULL;
	struct m_dev *m_dev = NULL;

	ENTER();

	if (!cardp) {
		PRINTM(ERROR, "usb_card_rec structure is not valid\n");
		LEAVE();
		return BT_STATUS_FAILURE;
	}
	priv = cardp->priv;

	m_dev = &(priv->bt_dev.m_dev[BT_SEQ]);
	PRINTM(CMD, "BT %s: USB suspend\n", m_dev->name);

	if (priv->adapter->is_suspended == TRUE) {
		PRINTM(ERROR, "Device already suspended\n");
		LEAVE();
		return BT_STATUS_SUCCESS;
	}

	mbt_hci_suspend_dev(m_dev);
	skb_queue_purge(&priv->adapter->tx_queue);

	if (priv->adapter->hs_state != HS_ACTIVATED) {
#ifdef BLE_WAKEUP
		/** Set BLE Wake up pattern */
		if (BT_STATUS_SUCCESS != bt_config_ble_wakeup(priv, FALSE))
			PRINTM(ERROR, "BT: Set ble wakeup pattern fail!\n");
#endif

		if (BT_STATUS_SUCCESS != bt_enable_hs(priv, FALSE)) {
			PRINTM(CMD, "BT: HS not actived, suspend fail!\n");
			if (BT_STATUS_SUCCESS != bt_enable_hs(priv, FALSE)) {
				PRINTM(CMD,
				       "BT: HS not actived the second time, force to suspend!\n");
			}
		}
	}

	priv->adapter->is_suspended = TRUE;

	spin_lock_irq(&cardp->txlock);
	if (!(PMSG_IS_AUTO(message) && cardp->tx_in_flight)) {
		set_bit(BT_USB_SUSPENDING, &cardp->flags);
		spin_unlock_irq(&cardp->txlock);
	} else {
		spin_unlock_irq(&cardp->txlock);
		return -EBUSY;
	}

	usb_stop_rx_traffic(cardp);
	usb_kill_anchored_urbs(&cardp->tx_anchor);
	usb_free_frags(priv);

	PRINTM(CMD, "ready to suspend BT USB\n");
	LEAVE();
	return BT_STATUS_SUCCESS;
}

/**
 *  @brief Handle resume
 *
 *  @param intf		Pointer to usb_interface
 *
 *  @return		BT_STATUS_SUCCESS
 */
static int
bt_usb_resume(struct usb_interface *intf)
{
	int ret = BT_STATUS_SUCCESS;
	struct usb_card_rec *cardp = usb_get_intfdata(intf);
	struct m_dev *m_dev = NULL;
	bt_private *priv = NULL;
	ENTER();

	if (!cardp) {
		PRINTM(ERROR, "usb_card_rec structure is not valid\n");
		LEAVE();
		return BT_STATUS_FAILURE;
	}

	priv = cardp->priv;
	m_dev = &(priv->bt_dev.m_dev[BT_SEQ]);
	PRINTM(CMD, "BT %s: USB resume\n", m_dev->name);

	if (priv->adapter->is_suspended == FALSE) {
		PRINTM(ERROR, "Device already resumed\n");
		LEAVE();
		return BT_STATUS_SUCCESS;
	}

	priv->adapter->is_suspended = FALSE;
#ifdef BLE_WAKEUP
	if (priv->ble_wakeup_buf) {
		PRINTM(CMD, "BT: Send system resume event\n");
		bt_send_system_event(priv, FALSE);
	}
#endif
	mbt_hci_resume_dev(m_dev);
	sbi_usb_wakeup_firmware(priv);

	if (test_bit(BT_USB_INTR_RUNNING, &cardp->flags)) {
		/* Submit Rx Interrupt URB (For Events) */
		ret = usb_submit_bt_intr_urb(priv, GFP_ATOMIC);
		if (ret < 0) {
			clear_bit(BT_USB_INTR_RUNNING, &cardp->flags);
			goto done;
		}
	}

	if (test_bit(BT_USB_BULK_RUNNING, &cardp->flags)) {
		/* Submit Rx Bulk URB (For ACL Data) */
		ret = usb_submit_bt_bulk_urb(priv, GFP_ATOMIC);
		if (ret < 0) {
			usb_kill_anchored_urbs(&cardp->intr_anchor);
			goto done;
		}
	}

#ifdef USB_SCO_SUPPORT
	if (test_bit(BT_USB_ISOC_RUNNING, &cardp->flags)) {
		if (usb_submit_bt_isoc_urb(priv, GFP_KERNEL) < 0)
			clear_bit(BT_USB_ISOC_RUNNING, &cardp->flags);
		else
			usb_submit_bt_isoc_urb(priv, GFP_KERNEL);
	}
#endif

	clear_bit(BT_USB_SUSPENDING, &cardp->flags);
	priv->adapter->hs_state = HS_DEACTIVATED;
	PRINTM(CMD, "BT:%s: HS DEACTIVATED in Resume!\n", m_dev->name);

done:
	LEAVE();
	return ret;
}
#endif

/********************************************************
		Global Fucntions
********************************************************/
void
usb_free_frags(bt_private *priv)
{
	unsigned long flags;
	struct m_dev *mbt_dev = &priv->bt_dev.m_dev[BT_SEQ];

	spin_lock_irqsave(&mbt_dev->rxlock, flags);

	kfree_skb(mbt_dev->evt_skb);
	mbt_dev->evt_skb = NULL;

	kfree_skb(mbt_dev->acl_skb);
	mbt_dev->acl_skb = NULL;

	kfree_skb(mbt_dev->sco_skb);
	mbt_dev->sco_skb = NULL;

	spin_unlock_irqrestore(&mbt_dev->rxlock, flags);
}

int
usb_flush(bt_private *priv)
{
	struct usb_card_rec *card = (struct usb_card_rec *)priv->bt_dev.card;

	if (card)
		usb_kill_anchored_urbs(&card->tx_anchor);

	usb_free_frags(priv);
	return 0;
}

#ifdef USB_SCO_SUPPORT

void
usb_char_notify(bt_private *priv, unsigned int arg)
{
	ENTER();
	if (!priv) {
		LEAVE();
		return;
	}
	if (arg == 1)
		usb_set_isoc_if(priv);
	else
		usb_unset_isoc_if(priv);
	LEAVE();
}

#endif /* USB_SCO_SUPPORT */

/**
 *  @brief bt driver call this function to register to bus driver
 *  This function will be used to register bt driver's add/remove
 *  callback function.
 *
 *  @return	BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int *
sbi_usb_register(void)
{
	int *ret;
	ENTER();

	PRINTM(MSG, "NXP Bluetooth USB driver\n");

	/*
	 * API registers the NXP USB driver
	 * to the USB system
	 */
	if (usb_register(&bt_usb_driver)) {
		PRINTM(FATAL, "USB Driver Registration Failed\n");
		return NULL;
	} else {
		ret = (int *)1;
	}

	LEAVE();
	return ret;
}

/**
 *  @brief bt driver call this function to unregister to bus driver
 *  This function will be used to unregister bt driver.
 *
 *  @return	NA
 */
void
sbi_usb_unregister(void)
{
	ENTER();

	/* API unregisters the driver from USB subsystem */
	usb_deregister(&bt_usb_driver);

	LEAVE();
	return;
}

/**
 *  @brief bt driver calls this function to register the device
 *
 *  @param priv	A pointer to bt_private structure
 *  @return	BT_STATUS_SUCCESS
 */
static int
sbi_usb_register_dev(bt_private *priv)
{
	struct usb_card_rec *card = (struct usb_card_rec *)priv->bt_dev.card;
	int ret = BT_STATUS_SUCCESS;

	ENTER();

	PRINTM(MSG, "Usb register device\n");
	priv->hotplug_device = &card->udev->dev;
	memcpy(priv->bt_dev.name, "bt_usb0", sizeof("bt_usb0"));

	if (card->boot_state == USB_FW_DNLD) {
		LEAVE();
		return ret;
	}

	ret = usb_autopm_get_interface(card->intf);
	if (ret < 0) {
		LEAVE();
		return ret;
	}

	card->intf->needs_remote_wakeup = 1;

	if (test_and_set_bit(BT_USB_INTR_RUNNING, &card->flags))
		goto done;

	/* Submit Rx Interrupt URB (For Events) */
	ret = usb_submit_bt_intr_urb(priv, GFP_ATOMIC);
	if (ret < 0)
		goto failed;

	/* Submit Rx Bulk URB (For ACL Data) */
	ret = usb_submit_bt_bulk_urb(priv, GFP_ATOMIC);
	if (ret < 0) {
		usb_kill_anchored_urbs(&card->intr_anchor);
		goto failed;
	}

	set_bit(BT_USB_BULK_RUNNING, &card->flags);

done:
	usb_autopm_put_interface(card->intf);
	LEAVE();
	return BT_STATUS_SUCCESS;

failed:
	clear_bit(BT_USB_INTR_RUNNING, &card->flags);
	usb_autopm_put_interface(card->intf);
	LEAVE();
	return ret;
}

/**
 *  @brief bt driver calls this function to unregister the device
 *
 *  @param priv		A pointer to bt_private structure
 *  @return		BT_STATUS_SUCCESS
 */
static int
sbi_usb_unregister_dev(bt_private *priv)
{
	struct usb_card_rec *card = (struct usb_card_rec *)priv->bt_dev.card;
	int err;

	ENTER();

	PRINTM(MSG, "Usb unregister device\n");
	clear_bit(BT_USB_ISOC_RUNNING, &card->flags);
	clear_bit(BT_USB_BULK_RUNNING, &card->flags);
	clear_bit(BT_USB_INTR_RUNNING, &card->flags);

#ifdef USB_SCO_SUPPORT
	cancel_work_sync(&card->work);
#endif

	usb_stop_rx_traffic(card);
	usb_kill_anchored_urbs(&card->tx_anchor);

	err = usb_autopm_get_interface(card->intf);
	if (err < 0) {
		LEAVE();
		return err;
	}

	card->intf->needs_remote_wakeup = 0;
	usb_autopm_put_interface(card->intf);

	LEAVE();
	return BT_STATUS_SUCCESS;
}

/**
 *  @brief This function sends data to the card.
 *
 *  @param priv		A pointer to bt_private structure
 *  @param skb		A pointer to sk_buff structure
 *  @return		BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
static int
sbi_usb_host_to_card(bt_private *priv, struct sk_buff *skb)
{
	struct usb_card_rec *card = (struct usb_card_rec *)priv->bt_dev.card;
	struct usb_ctrlrequest *req = NULL;
	struct urb *urb = NULL;
	unsigned int pipe;
	int len, mtu, i, offset = 0;
	u8 *buf = NULL;

	ENTER();

	/* No BT Specific Header for USB interface */
	if (!skb->len || (skb->len > BT_UPLD_SIZE)) {
		PRINTM(ERROR, "Tx Error: Bad skb length %d : %d\n", skb->len,
		       BT_UPLD_SIZE);
		LEAVE();
		return BT_STATUS_FAILURE;
	}

	if (bt_cb(skb)->pkt_type == MRVL_VENDOR_PKT)
		PRINTM(CMD, "DNLD_CMD: ocf_ogf=0x%x len=%d\n",
		       __le16_to_cpu(*((u16 *) & skb->data[0])), skb->len);

	buf = kmalloc(skb->len, GFP_ATOMIC);
	if (!buf) {
		LEAVE();
		return -ENOMEM;
	}
	memcpy(buf, skb->data, skb->len);

	switch (bt_cb(skb)->pkt_type) {

	case HCI_COMMAND_PKT:
	case MRVL_VENDOR_PKT:
		urb = usb_alloc_urb(0, GFP_ATOMIC);
		if (!urb)
			goto error;

		if (card->bulk_cmd_ep) {
			pipe = usb_sndbulkpipe(card->udev,
					       card->bulk_cmd_ep->
					       bEndpointAddress);

			usb_fill_bulk_urb(urb, card->udev, pipe,
					  buf, skb->len, usb_tx_complete, priv);
		} else {
			req = kmalloc(sizeof(*req), GFP_ATOMIC);
			if (!req)
				goto error;

			req->bRequestType = card->cmdreq_type;
			req->bRequest = 0;
			req->wIndex = 0;
			req->wValue = 0;
			req->wLength = __cpu_to_le16(skb->len);

			pipe = usb_sndctrlpipe(card->udev, BT_USB_EP_CMD);

			usb_fill_control_urb(urb, card->udev, pipe, (void *)req,
					     buf, skb->len, usb_tx_complete,
					     priv);
		}

		break;

	case HCI_ACLDATA_PKT:

		if (!card->bulk_tx_ep)
			goto error;

		urb = usb_alloc_urb(0, GFP_ATOMIC);
		if (!urb)
			goto error;

		pipe = usb_sndbulkpipe(card->udev,
				       card->bulk_tx_ep->bEndpointAddress);

		usb_fill_bulk_urb(urb, card->udev, pipe,
				  buf, skb->len, usb_tx_complete, priv);
		break;

	case HCI_SCODATA_PKT:

		if (!card->isoc_tx_ep)
			goto error;

		urb = usb_alloc_urb(BT_USB_MAX_ISOC_FRAMES, GFP_ATOMIC);
		if (!urb)
			goto error;

		pipe = usb_sndisocpipe(card->udev,
				       card->isoc_tx_ep->bEndpointAddress);
		urb->dev = card->udev;
		urb->pipe = pipe;
		urb->context = priv;
		urb->complete = usb_isoc_tx_complete;
		urb->interval = card->isoc_tx_ep->bInterval;

		urb->transfer_flags = URB_ISO_ASAP;
		urb->transfer_buffer = buf;
		urb->transfer_buffer_length = skb->len;

		len = skb->len;
		mtu = le16_to_cpu(card->isoc_tx_ep->wMaxPacketSize);
		for (i = 0; i < BT_USB_MAX_ISOC_FRAMES && len >= mtu;
		     i++, offset += mtu, len -= mtu) {
			urb->iso_frame_desc[i].offset = offset;
			urb->iso_frame_desc[i].length = mtu;
		}

		if (len && i < BT_USB_MAX_ISOC_FRAMES) {
			urb->iso_frame_desc[i].offset = offset;
			urb->iso_frame_desc[i].length = len;
			i++;
		}
		urb->number_of_packets = i;

		goto skip_waking;

	default:
		PRINTM(MSG, "Unknown Packet type!\n");
		goto error;
	}

	if (inc_tx(priv)) {

		/* Currently no deferring of work allowed, return error */
		PRINTM(INFO, "inc_tx() failed\n");
		goto error;
	}

skip_waking:
	PRINTM(DATA, "BT: USB Wr: len=%d type=%d\n", skb->len,
	       bt_cb(skb)->pkt_type);
	DBG_HEXDUMP(DAT_D, "BT: USB Wr", skb->data, skb->len);

	usb_anchor_urb(urb, &card->tx_anchor);

	if (usb_submit_urb(urb, GFP_ATOMIC) < 0) {
		PRINTM(ERROR, "sbi_host_to_card: urb %p submission failed",
		       urb);
		kfree(urb->setup_packet);
		usb_unanchor_urb(urb);
		goto error;
	} else {
		usb_mark_last_busy(card->udev);
	}

	PRINTM(INFO, "Tx submit: %p urb %d pkt_type\n",
	       urb, bt_cb(skb)->pkt_type);

	usb_free_urb(urb);
	LEAVE();
	return BT_STATUS_SUCCESS;

error:
	PRINTM(INFO, "Tx submit failed: %p urb %d pkt_type\n",
	       urb, bt_cb(skb)->pkt_type);
	kfree(buf);
	usb_free_urb(urb);
	LEAVE();
	return BT_STATUS_FAILURE;
}

/**
 *  @brief This function initializes firmware
 *
 *  @param priv		A pointer to bt_private structure
 *  @return		BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
static int
sbi_usb_download_fw(bt_private *priv)
{
	int ret = BT_STATUS_SUCCESS;
	struct usb_card_rec *card = (struct usb_card_rec *)priv->bt_dev.card;

	ENTER();

	PRINTM(MSG, "Usb download firmware\n");
	if (!card) {
		PRINTM(ERROR, "BT: card  is NULL!\n");
		ret = BT_STATUS_FAILURE;
		goto exit;
	}

	if (TRUE && (card->boot_state != USB_FW_READY)) {
		if (bt_extflg_isset(priv, EXT_FW) == 0) {
			PRINTM(MSG, "BT FW download skipped\n");
			ret = BT_STATUS_SUCCESS;
			goto exit;
		}
		PRINTM(MSG, "FW is not Active, Needs to be downloaded\n");
		get_monotonic_time(&priv->req_fw_time);
		/* Download the main firmware */
		if (usb_download_firmware_w_helper(priv)) {
			PRINTM(INFO, "BT: FW download failed!\n");
			ret = BT_STATUS_FAILURE;
		}
		goto exit;
	} else {
		PRINTM(MSG, "FW is Active\n");
		/* Set it to NULL, no downloading firmware to card */
		priv->firmware = NULL;
		if (BT_STATUS_FAILURE == sbi_register_conf_dpc(priv)) {
			PRINTM(ERROR,
			       "BT: sbi_register_conf_dpc failed. Terminating d/w\n");
			ret = BT_STATUS_FAILURE;
			goto exit;
		}
	}

exit:
	LEAVE();
	return ret;
}

/**
 *  @brief configures hardware to quit deep sleep state
 *
 *  @param priv		A pointer to bt_private structure
 *  @return		BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
static int
sbi_usb_wakeup_firmware(bt_private *priv)
{
	int ret = BT_STATUS_SUCCESS;
	ENTER();

	/* No explicit wakeup for USB interface */
	priv->adapter->ps_state = PS_AWAKE;

	LEAVE();
	return ret;
}

static bt_if_ops usb_ops = {
	.register_dev = sbi_usb_register_dev,
	.unregister_dev = sbi_usb_unregister_dev,
	.download_fw = sbi_usb_download_fw,
	.host_to_card = sbi_usb_host_to_card,
	.get_device = sbi_get_usb_device,
	.wakeup_firmware = sbi_usb_wakeup_firmware,
};
