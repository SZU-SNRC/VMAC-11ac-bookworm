/*
 * Copyright (c) 2017 - 2020, Mohammed Elbadry
 *
 *
 * This file is part of V-MAC (Pub/Sub data-centric Multicast MAC layer)
 *
 * V-MAC is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike
 * 4.0 International License.
 *
 * You should have received a copy of the license along with this
 * work. If not, see <http://creativecommons.org/licenses/by-nc-sa/4.0/>.
 *
 */
#include "vmac.h"
#define DEBUG_VMAC
/**
 * @brief    netlink send frame from kernel to userspace
 *
 * @param      skb    The skb
 * @param[in]  enc    The encoding of frame
 * @param[in]  type    The type (i.e. data/interest/announcment/injected frame)
 * @param[in]  seq    The sequence of frame (if it has any)
 *
 *
 * @code{.unparsed}
 *  if there is a userspace process running to receive frame
 *      create memory based on size of frame and extra for control signals
 *      if memory was not created sucessfully
 *          return
 *      end If
 *      copy frame to new memory
 *      pass control signals (encoding, sequence, and type)
 *      set message netlink format to unicast and send
 *      if returned output < 0
 *          print logging message
 *      End If
 *  End If
 *  free memory of kernel from frame
 * @endcode
 */
static void nl_send(struct sk_buff *skb, u64 enc, u8 type, u16 seq)
{
    // printk(KERN_INFO "calling nl_send %s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
    struct nlmsghdr *nlh;
    struct sk_buff *skb_out;
    int res;
    int result_len;
    struct control txc;
    struct sock *nl_sk = getsock();
    uint64_t ence = (uint64_t)enc;
    uint16_t typee = (uint8_t)type;
    int pidt = getpidt();
    char bwsg = 0;
    char offset = 0;
    u8 val;
	// printk(KERN_INFO "33FRAME CAME OVER HERE %s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
    // return some control buffer, to clearify the tx status
    struct ieee80211_rx_status *status = IEEE80211_SKB_RXCB(skb);

    if (status->bw == RATE_INFO_BW_40)
    {
        bwsg |= 2;
    }
    if (status->enc_flags & RX_ENC_FLAG_SHORT_GI)
    {
        bwsg |= 1;
    }

    if (status->encoding & RX_ENC_HT)
    {
        offset = 12;
    }
    if (pidt != -1)
    {
        printk(KERN_INFO "skb->len is %d, %s %s %d\n", skb->len, __FILE__, __FUNCTION__, __LINE__);
        skb_out = nlmsg_new(skb->len + 115, GFP_KERNEL); /* extra len for headers and buffer for firmware and driver cross communication */
        // printk(KERN_INFO "create a new SKB %s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
        if (!skb_out)
        {
            printk(KERN_INFO "VMAC ERROR: Failed to allocate...%s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
            return;
        }
        result_len = skb->len + 108;
        result_len = skb->len - 4 + 100;
        if (result_len < 100)
        {
            result_len = 100;
        }
        nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, result_len, 0);
        printk(KERN_INFO "Add a new netlink message to the new skb %s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
        nlh->nlmsg_pid = pidt;
        val = status->rate_idx + offset;
        NETLINK_CB(skb_out).dst_group = 0;
        memcpy(&txc.enc[0], &ence, 8);
        memcpy(&txc.seq[0], &seq, 2);
        memcpy(&txc.type, &typee, 1);
        // memcpy(&txc.bwsg, &bwsg, 1);
        // memcpy(&txc.rate_idx, &val, 1);
        // memcpy(&txc.signal, &status->signal, 1);
        memcpy(nlmsg_data(nlh), &txc, sizeof(struct control));
        memcpy(nlmsg_data(nlh) + sizeof(struct control), skb->data, skb->len - 4);
        // printk(KERN_INFO "ence, seq, typee memcpy done %s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
        // printk(KERN_INFO "strings should be buffer: %s\n", nlmsg_data(nlh) + sizeof(struct control));
        // print_hex_dump(KERN_DEBUG, "raw data: ", DUMP_PREFIX_ADDRESS,
        //                16, 1, nlmsg_data(nlh) + sizeof(struct control), 6, true);

        // print msg to userspace
		#ifdef DEBUG_KB
			printk(KERN_INFO "KB- Recv a msg: Package type: %d, Seq : %d, Enc hex:0x%llx\n",nlh->nlmsg_type, seq, enc);
			// print_hex_dump(KERN_DEBUG, "1KB- raw data: ", DUMP_PREFIX_ADDRESS,
            //            16, 1, nlmsg_data(nlh) + sizeof(struct control), 6, true);
            // print_hex_dump(KERN_DEBUG, "2KB- raw data: ", DUMP_PREFIX_ADDRESS,
            //            16, 1, nlmsg_data(nlh) + sizeof(struct control) +6, 4, true);
            // print_hex_dump(KERN_DEBUG, "3KB- raw data: ", DUMP_PREFIX_ADDRESS,
            //            16, 1, nlmsg_data(nlh) + sizeof(struct control) , 10, true);
			// printk(KERN_INFO "KB- Buffer: %s\n", nlmsg_data(nlh) + sizeof(struct control));
			// printk(KERN_INFO "KB- Buffer: %s\n", nlmsg_data(nlh) + sizeof(struct control));
		#endif
        res = nlmsg_unicast(nl_sk, skb_out, pidt);
        printk(KERN_INFO "after nlmsg_unicast %s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
        if (res < 0)
        {
#ifdef DEBUG_VMAC
            printk(KERN_INFO "res: %d\n",res);
            printk(KERN_INFO "nlmsg_unicast Failed... %s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
#endif
        }
    }
    kfree_skb(skb);
    printk(KERN_INFO "RX DONE. After kfree_skb. %s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
    // nlmsg_free(skb_out);
    // printk(KERN_INFO "after nlmsg_free %s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
}

/**
 * @brief    vmac rx main function note frame types are the following
 * - 0: Interest
 * - 1: Data
 * - 2: DACK
 * - 3: (used by userspace only to register, never comes to this function)
 * - 4: Announcment
 * - 5: Frame injection
 *
 * @param      skb    The socket buffer to be processed
 *
 * Pseudo Code
 *
 * @code{.unparsed}
 *  pull vmac header from frame
 *  if frame type is 0
 *   set sequence value to 0 //pass to upper layer no further action
 *  else if type is 1 //data
 *   read data V-MAC header
 *   read sequence number of frame
 *   find struct for encoding within lookup table
 *   If struct does not exist
 *    free frame
 *    return
 *   else
 *    increment timeout for encoding in LET by 30 seconds
 *   End If
 *
 *   If received frame is after highest received sequence number
 *    while latest sequence number stored is less than received frame seq
 *     increment latest sequence number
 *     indicate in sliding window frame is lost
 *    End While
 *   else if received frame sequence number has been received is indicated by sliding window
 *    free frame
 *    return
 *   End If
 *
 *   If frame received sequence number is within window and has not been received before
 *    set sliding window index value for that frame to 1
 *   EndIf
 *
 *   If we have NOT calculated time of first frame
 *    record time of reception
 *   else if we have NOT calculated time of second frame
 *    record time of reception
 *    calculate alpha by subtracting second frame timing from first and dividing by sequence number difference
 *    Set first frame timing to 0 //(i.e. reset)
 *      End If
 *
 *      set last index received value to received frame sequence number// note this is a bug if frame received is retransmission
 *      If frame is 5th frame within round
 *       Calculate actual round number (not sequence numeber)
 *       recall request DACK function passing encoding and round number
 *       set value for new round number
 *      End If
 *      pull Data type header from frame
 *  else if type is 2
 *   Look up encoding at rx table
 *   look up encoding at tx table
 *   read number of holes in DACK header
 *   read round number in DACK header
 *   pull DACK header from frame
 *   if entry exists at tx table
 *    set data rate to 0 (i.e. 1 mbps lowest)
 *    increment number of dacks received //statistics purposes
 *    set i to 0
 *    while i is less than number of holes
 *     read hole
 *     read le
 *     read re
 *     while le <re && le < sent sequence number
 *      if DACK received round is greater than round recorder for last retx request
 *       lock tx table entry for encoding
 *       copy frame from retransmission buffer
 *       unlock tx table entry for encoding
 *       if frame is valid
 *        set retransmission pacing to current DACK round + 6 (emperically)
 *        call function retrx passing frame and 255 (i.e. data rate selected by function)
 *        vmact increment frame count (statistics purposes)
 *       End If
 *      End If
 *      increment le
 *     End While
 *     pull hole from frame
 *    End While
 *   End If
 *   If entry exists at rx table
 *    if vmac rx entry succeeds at locking dacklock
 *     If current radio is still about to send and round is the same
 *      If radio head another dack already
 *       set dack sending signal to 0
 *       delete pending DACK from transmission
 *      else
 *       increment dack heard
 *      End If
 *     End If
 *     unlock rx entry dacklock
 *    End If
 *   End If
 *   free frame
 *   return
 *  else if type is 4
 *   set sequence to 0 //no further action here
 *  else if type is 5
 *   read sequence number from V-MAC data type header
 *   pull Data type header from frame
 *  else
 *   Free kernel memory from the frame (not V-MAC frame)
 *  End If
 *  call nl_send passing frame,encoding, type of frame, and sequence number (if exists)
 * @endcode
 */
void vmac_rx(struct sk_buff *skb)
{
    printk(KERN_INFO "RECEIVED a DATA FROM DONGLE %s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
    u8 type;
    u16 seq, holes, le, re, i = 0, round;
    u64 enc;
    struct encoding_tx *vmact;
    struct ieee80211_hdr hdr;
    struct encoding_rx *vmacr;
    struct vmac_hole *hole;
    struct sk_buff *skb2 = NULL;
    struct vmac_DACK *ddr;
    int maxretx = 20;
    int counter = 0;
    u8 src[ETH_ALEN] __aligned(2) = {0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe};
    u8 dest[ETH_ALEN] __aligned(2) = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    u8 bssid[ETH_ALEN] __aligned(2) = {0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe};
    struct vmac_data *vdr;
    struct vmac_hdr *vmachdr = (struct vmac_hdr *)skb->data;
    type = vmachdr->type;
    enc = vmachdr->enc;
    hdr.duration_id = 11;
    memcpy(hdr.addr1, dest, ETH_ALEN); // was target
    memcpy(hdr.addr2, src, ETH_ALEN);  // was target
    memcpy(hdr.addr3, bssid, ETH_ALEN);
    hdr.frame_control = cpu_to_le16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_DATA);
    skb_pull(skb, sizeof(struct vmac_hdr));
    #ifdef DEBUG_VMAC
        printk(KERN_INFO "Encoding received is: %llu, type is %d; %s %s %d\n", enc, type, __FILE__, __FUNCTION__, __LINE__);
    #endif
    /* interest */
    if (type == VMAC_HDR_INTEREST)
    {
        printk(KERN_INFO "RECEIVED AN INTEREST\n");
        seq = 0;
    } /* Data */
    else if (type == VMAC_HDR_DATA)
    {
        printk(KERN_INFO "RECEIVED A DATA\n");
        vdr = (struct vmac_data *)skb->data;
        seq = vdr->seq;
        vmacr = find_rx(RX_TABLE, enc);
        if (!vmacr || vmacr == NULL)
        {
            printk(KERN_INFO "Does not exist freeing memory and dropping y'know casual. %s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
            kfree_skb(skb);
            return;
        }
        else
        {
            mod_timer(&vmacr->enc_timeout, jiffies + msecs_to_jiffies(10000));
        }

        if (vmacr->latest < vdr->seq) // uncomment once checked clear
        {
            while (vmacr->latest < vdr->seq)
            {
                vmacr->latest++;
                vmacr->window[vmacr->latest >= WINDOW ? vmacr->latest % WINDOW : vmacr->latest] = 0;
            }
        }
        else if (vmacr->window[seq >= WINDOW ? seq % WINDOW : seq] == 1) // unnecessary: &&vdr->seq>=(vmacr->latest>window?vmacr->latest%RX_WINDOW:0)
        {
            kfree_skb(skb);
            return;
        }

        if (vdr->seq >= (vmacr->latest >= WINDOW ? vmacr->latest % WINDOW : 0))
        {
            vmacr->window[(seq >= WINDOW ? vdr->seq % WINDOW : vdr->seq)] = 1;
        }

        if (vmacr->firstFrame == 0)
        {
            vmacr->firstFrame = jiffies;
        }
        else if (vmacr->SecondFrame == 0)
        {
            vmacr->SecondFrame = jiffies;
            vmacr->alpha = (((jiffies - vmacr->firstFrame) / (vdr->seq - vmacr->lastin)));
            vmacr->firstFrame = 0;
        }
        vmacr->lastin = vdr->seq;
        // MODIFY: close DACK
        // if (vmacr->round <= vdr->seq - 5)
        // {
        //     vmacr->round = vdr->seq / 5;
        //     request_DACK(enc, vmacr->round);
        //     vmacr->round = vdr->seq;
        // }
        skb_pull(skb, sizeof(struct vmac_data));
        #ifdef DEBUG_VMAC
            printk(KERN_INFO "DATA SEQ: %d", vdr->seq);
        #endif
    } /* DACK */
    else if (type == VMAC_HDR_DACK)
    {
#ifdef DEBUG_MO
        printk(KERN_INFO "LOOKING AT DACK %s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
#endif
        i = 0;
        vmacr = find_rx(RX_TABLE, enc);
        vmact = find_tx(TX_TABLE, enc);
        vmacr = NULL;
        ddr = (struct vmac_DACK *)skb->data;
        holes = ddr->holes;
        round = ddr->round;
        skb_pull(skb, sizeof(struct vmac_DACK));
#ifdef DEBUG_MO
        printk(KERN_INFO "Encoding of DACK = %lld, %s %s %d\n", enc, __FILE__, __FUNCTION__, __LINE__);
#endif
        if (vmact && vmact != NULL)
        {
            spin_lock(&vmact->seqlock);
            seq = vmact->seq;
            spin_unlock(&vmact->seqlock);
#ifdef DEBUG_MO
            printk(KERN_INFO "Encoding of DACK = %lld,  holes= %d, %s %s %d\n", enc, holes, __FILE__, __FUNCTION__, __LINE__);
#endif
            vmact->dackcounter++;
            hole = (struct vmac_hole *)skb->data;
            while (i < holes && holes != 0)
            {
                hole = (struct vmac_hole *)skb->data;
                le = hole->le;
                re = hole->re;
                i++;
                while (le < re && le < seq)
                {
                    if (round >= vmact->timer[(le >= WINDOW_TX ? le % WINDOW_TX : le)] && le >= (seq < WINDOW_TX ? 0 : seq - (WINDOW_TX)))
                    {
                        if (maxretx <= counter)
                            break; /* break off or kernel will crash */
                        if (vmact->retransmission_buffer[(le > WINDOW_TX ? le % WINDOW_TX : le)])
                        {
                            skb2 = skb_copy(vmact->retransmission_buffer[(le >= WINDOW_TX ? le % WINDOW_TX : le)], GFP_KERNEL); // mo here
                            counter++;
                        }
                        vmact->timer[le % WINDOW_TX] = round + 6;
                        if (skb2)
                        {
                            //                            retrx(skb2, 255); mo here
                            vmac_send_hack(skb2);
                            vmact->framecount++;
                        }
                    }
                    le++;
                }
                skb_pull(skb, sizeof(struct vmac_hole)); // dont pull dumbass might be needed at bottom........or...convolute things, probably easier. didn't work, will just make a copy safer....(kinda lazy to do better way lol)
            }
        }
        if (vmacr && vmacr != NULL)
        {
            if (spin_trylock(&vmacr->dacklok))
            {
                if (vmacr->dac_info.send == 1 && vmacr->dac_info.round == round)
                {
                    if (vmacr->dac_info.dacksheard >= 1)
                    {
                        vmacr->dac_info.send = 0;
                    }
                    else
                        vmacr->dac_info.dacksheard++;
                }
                spin_unlock(&vmacr->dacklok);
            }
        }
        kfree_skb(skb);
        return;
    } /* Announcement */
    else if (type == VMAC_HDR_ANOUNCMENT)
    {
        // printk(KERN_INFO "receive an ANOUNCMENT %s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
        seq = 0;
    } /* Injected frame */
    else if (type == VMAC_HDR_INJECTED)
    {
        vdr = (struct vmac_data *)skb->data;
        seq = vdr->seq;
        skb_pull(skb, sizeof(struct vmac_data));
    } /* Unknown frame type */
    else
    {
        kfree_skb(skb);
        return;
    }
    printk(KERN_INFO "Ready to call nl_send %s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
    nl_send(skb, enc, type, seq);
}


// useless
/**
 * @brief      Receives frames from low-level driver kernel module and filters V-MAC frames from non V-MAC frames.
 *
 * @param      hw    The hardware struct
 * @param      skb   The skb
 *
 * Pseudo Code
 *
 * @code{.unparsed}
 *  if received frame 802.11 header has at first two bytes value 0xfe //(we assume it is V-MAC)
 *      Remove 802.11 header
 *      read V-MAC header
 *      if frame type is interest, data, announcment, or frame injection
 *          call vmac_rx passing frame  i.e. core
 *      else if frame type is DACK
 *          add frame to management queue
 *      else
 *          free kernel memory from frame i.e. not V-MAC frame
 *  Else
 *      free kernel memory of frame     i.e. not V-MAC frame
 *  End If
 * @endcode
 */
// void ieee80211_rx_vmac(struct ieee80211_hw *hw, struct sk_buff *skb)
// {
//     printk(KERN_INFO "66 Recv a msg from radio FRAME CAME OVER HERE %s %s %d\n", __FILE__, __FUNCTION__, __LINE__);

//     struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
//     struct vmac_hdr *vmachdr;
// #ifdef DEBUG_VMAC
//     struct ieee80211_rx_status *status = IEEE80211_SKB_RXCB(skb);
// #endif
//     u8 type;
//     if (hdr->addr2[0] == 0xfe && hdr->addr2[1] == 0xfe)
//     {
// #ifdef DEBUG_VMAC
//         if (status->enc_flags & RX_ENC_FLAG_SHORT_GI)
//         {
//             printk(KERN_INFO "VMAC: Short GI %s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
//         }
//         if (status->bw == RATE_INFO_BW_40)
//         {
//             printk(KERN_INFO "VMAC: BW40 %s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
//         }
//         printk(KERN_INFO "V-MAC, Rate: %d, %s %s %d\n", status->rate_idx, __FILE__, __FUNCTION__, __LINE__);
//         printk(KERN_INFO "VMAC: signal val: %d, %s %s %d\n", -status->signal, __FILE__, __FUNCTION__, __LINE__);
// #endif

//         skb_pull(skb, sizeof(struct ieee80211_hdr));
//         vmachdr = (struct vmac_hdr *)skb->data;
//         type = vmachdr->type;
//         if (type == VMAC_HDR_INTEREST || type == VMAC_HDR_DATA || type == VMAC_HDR_ANOUNCMENT || type == VMAC_HDR_INJECTED)
//         {
// 	        printk(KERN_INFO "44 Recv a msg from radio FRAME CAME OVER HERE %s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
//             vmac_rx(skb);
//         }
//         else if (type == VMAC_HDR_DACK)
//         {
// 	        printk(KERN_INFO "55 Recv a msg from radio FRAME CAME OVER HERE %s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
//             // add_mgmt(skb); mo here
//         }
//         else
//         {
// #ifdef DEBUG_VMAC
//             printk(KERN_INFO "ERROR: Received type= %d, %s %s %d\n", type, __FILE__, __FUNCTION__, __LINE__);
// #endif
//             kfree_skb(skb);
//         }
//     }
//     else
//     {
// #ifdef ENABLE_OVERHEARING
// #ifdef DEBUG_VMAC
//         if (status->enc_flags & RX_ENC_FLAG_SHORT_GI)
//         {
//             printk(KERN_INFO "VMAC: Short GI\n");
//         }
//         if (status->bw == RATE_INFO_BW_40)
//         {
//             printk(KERN_INFO "VMAC: BW40\n");
//         }
//         if (status->rate_idx != 0)
//         {
//             printk(KERN_INFO "V-MAC, Rate: %d\n", status->rate_idx);
//             printk(KERN_INFO "VMAC: signal val: %d\n", -status->signal);
//         }
// #endif
//         printk(KERN_INFO "ready call nl_send in OVERHEARING %s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
//         nl_send(skb, 0, V_MAC_OVERHEAR, 0);
// #else
//         kfree_skb(skb);
// #endif
//     }
// }
// EXPORT_SYMBOL(ieee80211_rx_vmac);
