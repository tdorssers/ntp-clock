/*********************************************
 * Author: Guido Socher
 * Copyright:LGPL V2
 * See http://www.gnu.org/licenses/old-licenses/lgpl-2.0.html
 *
 * Modified by: Tim Dorssers
 * - Improved lease time precision to one second ticks at the cost of larger code size
 * - Changed renewal to start at 50% of lease time, like most DHCP clients
 * - Added support for handling lease time longer then one day, including infinity
 * - Added assigned DNS parameter support (DNS defaults to 8.8.8.8)
 * - Replaced 3 while loops in make_dhcp_message_template() by memset to save 6 bytes of code
 * - Made several optimizations in terms of code size throughout the DHCP client code
 * - Changed packetloop_dhcp_initial_ip_assignment() to retry at exponential increasing intervals and removed initial delay
 * - Changed packetloop_dhcp_renewhandler() to retry at intervals of 12.5% of lease time
 * - Added dhcp_get_info()
 * - Added init_dhcp()
 * - Added dhcp_tick()
 * - Removed dhcp_6sec_tick()
 *
 * A DHCP client.
 * This code uses the UDP_client framework. You need to enable UDP_client in ip_config.h to use this.
 *
 * DHCP requires the periodic renewal of addresses. For this 
 * purpose you must call the function dhcp_tick() every sec.
 * If you do not call it then you can still get an initial IP
 * (without retry in case of failure) but there will be no
 * lease renewal.
 *********************************************/
#include <avr/io.h>
#include <avr/pgmspace.h>
#include <string.h>
#include <stdlib.h>
#include "net.h"
#include "enc28j60.h"
#include "ip_arp_udp_tcp.h"
#include "ip_config.h"

#ifndef UDP_client
#error "ERROR: you need to enable UDP_client support in ip_config.h to use the DHCP client"
#endif

static uint8_t dhcp_yiaddr[4]={0,0,0,0}; // your (client) IP
static uint8_t dhcp_opt_defaultgw[4]={0,0,0,0}; // default gw
static uint8_t dhcp_opt_mask[4]={0,0,0,0}; // net mask
static uint8_t dhcp_opt_server_id[4]={0,0,0,0}; // server ip
static uint8_t dhcp_opt_dns[4]={8,8,8,8}; // domain name server
static uint8_t dhcp_opt_message_type=0;
static uint8_t dhcp_tid=0;
static uint32_t dhcp_opt_leasetime=0xffffffff;
static uint32_t dhcp_cnt_down=0;
static uint8_t dhcp_init_state=0;
const char PROGMEM param_req_lst_end_of_opt[]={0x37,0x3,0x1,0x3,0x6,0xff,0x0}; // 55, len, subnet mask option, router option, dns option, end of options, 0
const char PROGMEM cookie[]={0x63,0x82,0x53,0x63};

// 
// The relevant RFCs are 
// DHCP protocol: http://tools.ietf.org/html/rfc1541
// newer version:
// DHCP protocol: http://tools.ietf.org/html/rfc2131
// message encoding: http://tools.ietf.org/html/rfc1533
//
// The normal message flow to get an IP address is:
// Client -> Server DHCPDISCOVER
// Server -> Client DHCPOFFER
// Client -> Server DHCPREQUEST
// Server -> Client DHCPACK
// There might be several seconds delay between the DHCPDISCOVER and
// the DHCPOFFER as the server does some test (e.g ping or arp) to see
// if the IP which is offered is really free.
//
// At lease renewal the message flow is:
// Client -> Server DHCPREQUEST
// Server -> Client DHCPACK
// The DHCPREQUEST for renewal is different from the one at initial assignment.
//
//
// DHCP_OPTION_OFFSET is a relative to UDP_DATA_P
#define DHCP_OPTION_OFFSET 240
#define MAGIC_COOKIE_P 236
#define DHCP_SRV_SRC_PORT 67
#define DHCP_SRV_DST_PORT 68
// message type values
#define DHCP_DISCOVER_V 0x01
#define DHCP_REQUEST_V 0x03

// Lease time renewal and time keeping.
void dhcp_tick(void){
	if (dhcp_cnt_down!=0xffffffff) dhcp_cnt_down--;
}

// This function writes a basic message template into buf
// It processes all fields excluding the options section.
// Most fields are initialized with zero.
void make_dhcp_message_template(uint8_t *buf,const uint8_t transactionID)
{
	uint8_t i=0;
	uint8_t allxff[6]={0xff,0xff,0xff,0xff,0xff,0xff}; // all of it can be used as mac, the first 4 can be used as IP

	send_udp_prepare(buf,DHCP_SRV_DST_PORT,allxff,DHCP_SRV_SRC_PORT,allxff);
	// source IP is 0.0.0.0
	memset(buf+IP_SRC_P,0,4);
	// now fill the bootstrap protocol layer starting at UDP_DATA_P
	buf[UDP_DATA_P]=1;// message type = boot request
	buf[UDP_DATA_P+1]=1;// hw type
	buf[UDP_DATA_P+2]=6;// mac len
	buf[UDP_DATA_P+3]=0;// hops
	// we use only one byte TIDs, we fill the first byte with 1 and
	// the rest with transactionID. The first byte is used to
	// distinguish initial requests from renew requests.
	buf[UDP_DATA_P+4]=1;
	i=0;
	while(i<3){
		buf[UDP_DATA_P+i+5]=transactionID;
		i++;
	}
	// set my own MAC the rest is empty:
	memset(buf+UDP_DATA_P+8,0,20);
	// own mac (send_udp_prepare did fill it at eth level):
	i=0;
	while(i<6){
		buf[UDP_DATA_P+i+28]=buf[ETH_SRC_MAC +i];
		i++;
	}
	// now we need to write 202 bytes of zero
	memset(buf+UDP_DATA_P+34,0,202);
	// DHCP magic cookie
	memcpy_P(buf+UDP_DATA_P+MAGIC_COOKIE_P,cookie,4);
}

// the answer to this message will come as a broadcast
uint8_t send_dhcp_discover(uint8_t *buf,const uint8_t transactionID)
{
	make_dhcp_message_template(buf,transactionID);
	// option dhcp message type:
	buf[UDP_DATA_P+DHCP_OPTION_OFFSET]=0x35; // 53
	buf[UDP_DATA_P+DHCP_OPTION_OFFSET+1]=1; //len
	buf[UDP_DATA_P+DHCP_OPTION_OFFSET+2]=DHCP_DISCOVER_V;
	// option parameter request list:
	memcpy_P(buf+UDP_DATA_P+DHCP_OPTION_OFFSET+3,param_req_lst_end_of_opt,7);
	// no padding
	// the length of the udp message part is now DHCP_OPTION_OFFSET+9
	send_udp_transmit(buf,DHCP_OPTION_OFFSET+9);
	return(0);
}

// scan the options field for the message type field
// and return its value.
//
// Value   Message Type
// -----   ------------
//   1     DHCPDISCOVER
//   2     DHCPOFFER  (server to client)
//   3     DHCPREQUEST
//   4     DHCPDECLINE
//   5     DHCPACK  (server to client)
//   6     DHCPNAK  (server to client)
//   7     DHCPRELEASE
// return 0 on message type not found otherwise the numeric
// value for the message type as shown in the table above.
uint8_t dhcp_get_message_type(uint8_t *buf,uint16_t plen)
{
	uint16_t option_idx;
	uint8_t option_len;
	// the smallest option is 3 bytes
	if (plen<(UDP_DATA_P+DHCP_OPTION_OFFSET+3)) return(0);
	// options are coded in the form: option_type,option_len,option_val
	option_idx=UDP_DATA_P+DHCP_OPTION_OFFSET;
	while(option_idx+2 <plen ){
		option_len=buf[option_idx+1];
		if ((option_len<1) || ((option_idx + option_len + 1)> plen)) break;
		if (buf[option_idx]==53){
			// found message type, return it:
			return(buf[option_idx+2]);
		}
		option_idx+=2+option_len;
	}
	return(0);
}

// use this on DHCPACK or DHCPOFFER messages to read "your ip address"
static uint8_t dhcp_get_yiaddr(uint8_t *buf,uint16_t plen)
{
	// DHCP offer up to options section is at least 0x100 bytes
	if (plen<0x100) return(0);
	if (buf[UDP_DATA_P+16]!=0){
		// we have a yiaddr
		memcpy(dhcp_yiaddr, buf+UDP_DATA_P+16, 4);
		return(1);
	}
	return(0);
}

// this will as well update dhcp_yiaddr
uint8_t is_dhcp_msg_for_me(uint8_t *buf,uint16_t plen,const uint8_t transactionID)
{
	// DHCP offer up to options section is at least 0x100 bytes
	if (plen<0x100) return(0);
	if (buf[UDP_SRC_PORT_L_P] != DHCP_SRV_SRC_PORT) return(0);
	if (buf[UDP_DATA_P]!=2) return(0); // message type DHCP boot reply =2
	if (buf[UDP_DATA_P+5]!=transactionID) return(0);
	if (buf[UDP_DATA_P+6]!=transactionID) return(0);
	return(1);

}

// check if this message was part of a renew or 
uint8_t dhcp_is_renew_tid(uint8_t *buf,uint16_t plen)
{
	if (plen<0x100) return(0);
	if (buf[UDP_DATA_P+4]==2) return(1); // we did set first byte in transaction ID to 2 to indicate renew request. This trick makes the processing of the DHCPACK message easier.
	return(0);
}

uint8_t dhcp_option_parser(uint8_t *buf,uint16_t plen)
{
	uint16_t option_idx;
	uint8_t option_len;
	uint8_t i;
	// the smallest option is 3 bytes
	if (plen<(UDP_DATA_P+DHCP_OPTION_OFFSET+3)) return(0);
	// options are coded in the form: option_type,option_len,option_val
	option_idx=UDP_DATA_P+DHCP_OPTION_OFFSET;
	while(option_idx+2 <plen ){
		option_len=buf[option_idx+1];
		if ((option_len<1) || ((option_idx + option_len + 1)> plen)) break;
		switch (buf[option_idx]){
			case 0: 
				option_idx=plen; // stop loop, we are reading some padding bytes here (should not happen)
				break;
			// subnet mask
			case 1: 
				if (option_len==4){
					memcpy(dhcp_opt_mask,buf+option_idx+2,4);
				}
				break;
			// router
			case 3: 
				if (option_len==4){
					memcpy(dhcp_opt_defaultgw,buf+option_idx+2,4);
				}
				break;
			// DNS
			case 6:
				memcpy(dhcp_opt_dns,buf+option_idx+2,4);
				break;
			// Lease time: throughout the protocol, times are to 
			// be represented in units of seconds.  The time value 
			// of 0xffffffff is reserved to represent "infinity". 
			// The max lease time size is therefore 32 bit. 
			// The code for this option is 51, and its length is 4
			// as per RFC 1533.
			case 51: 
				if (option_len==4){
					i=0;
					while(i<4){
						dhcp_opt_leasetime=(dhcp_opt_leasetime<<8) | buf[option_idx+i+2];
						i++;
					}
				}
				dhcp_cnt_down=dhcp_opt_leasetime/2;
				break;
			// DHCP Msg Type
			case 53: 
				dhcp_opt_message_type=buf[option_idx+2];
				break;
			// rfc 2131: A DHCP server always returns its 
			// own address in the 'server identifier' option
			case 54: 
				if (option_len==4){
					memcpy(dhcp_opt_server_id,buf+option_idx+2,4);
				}
				break;
		}
		option_idx+=2+option_len;
	}
	return(1);
}

uint8_t make_dhcp_opt_ip(uint8_t *buf, uint8_t opt, uint8_t *src) {
	if (src[0]!=0){
		*buf++=opt; // option
		*buf++=4; // len
		memcpy(buf,src, 4);
		return(6);
	}
	return(0);
}

// the answer to this message will come as a broadcast
static uint8_t send_dhcp_request(uint8_t *buf,const uint8_t transactionID)
{
	uint8_t i;
	make_dhcp_message_template(buf,transactionID);
	// option dhcp message type:
	buf[UDP_DATA_P+DHCP_OPTION_OFFSET]=0x35; // 53
	buf[UDP_DATA_P+DHCP_OPTION_OFFSET+1]=1; //len
	buf[UDP_DATA_P+DHCP_OPTION_OFFSET+2]=DHCP_REQUEST_V;
	i=3;
	// 54=server identifier:
	i+=make_dhcp_opt_ip(buf+UDP_DATA_P+DHCP_OPTION_OFFSET+i,0x36,dhcp_opt_server_id);
	// 50=requested IP address:
	i+=make_dhcp_opt_ip(buf+UDP_DATA_P+DHCP_OPTION_OFFSET+i,0x32,dhcp_yiaddr);
	// option parameter request list:
	memcpy_P(buf+UDP_DATA_P+DHCP_OPTION_OFFSET+i,param_req_lst_end_of_opt,7);
	// the length of the udp message part is now DHCP_OPTION_OFFSET+i+6
	send_udp_transmit(buf,DHCP_OPTION_OFFSET+i+6);
	return(0);
}

// The renew procedure is described in rfc2131. 
// We send DHCPREQUEST and 'server identifier' MUST NOT be filled 
// in, 'requested IP address' option MUST NOT be filled in, 'ciaddr' 
// MUST be filled. 
// The rfc suggest that I can send the DHCPREQUEST in this case as
// a unicast message and not as a broadcast message but test with
// various DHCP servers show that not all of them listen to
// unicast. We send therefor a broadcast message but we expect
// a unicast answer directly to our mac and IP.
static uint8_t send_dhcp_renew_request(uint8_t *buf,const uint8_t transactionID,uint8_t *yiaddr)
{
	make_dhcp_message_template(buf,transactionID);
	buf[UDP_DATA_P+4]=2; // set first byte in transaction ID to 2 to indicate renew_request. This trick makes the processing of the DHCPACK message easier.
	// source IP must be my IP since we renew
	memcpy(buf+IP_SRC_P, yiaddr, 4); // ip level source IP
	//
	memcpy(buf+UDP_DATA_P+12,yiaddr, 4); // ciaddr
	// option dhcp message type:
	buf[UDP_DATA_P+DHCP_OPTION_OFFSET]=0x35; // 53
	buf[UDP_DATA_P+DHCP_OPTION_OFFSET+1]=1; //len
	buf[UDP_DATA_P+DHCP_OPTION_OFFSET+2]=DHCP_REQUEST_V;
	// no option parameter request list is needed at renew
	send_udp_transmit(buf,DHCP_OPTION_OFFSET+3);
	// we will get a unicast answer, reception of broadcast packets is turned off
	return(0);
}

// Initial_tid can be a random number for every board. E.g the last digit
// of the mac address. It is not so important that the number is random.
// It is more important that it is unique and no other board on the same
// LAN has the same number. This is because there might be a power outage
// and all boards reboot afterwards at the same time. At that moment they
// must all have different TIDs otherwise there will be an IP address mess-up.
void init_dhcp(uint8_t initial_tid) {
	dhcp_init_state=1;
	dhcp_yiaddr[0]=0; // invalidate IP
	dhcp_tid=initial_tid;
}

// init_dhcp() must be called before calling this function in your packetloop.
// The function returns 1 once we have a valid IP. 
uint8_t packetloop_dhcp_initial_ip_assignment(uint8_t *buf,uint16_t plen){
	uint8_t cmd;
	if (!enc28j60linkup()) return(0); // do nothing if the link is down
	if (plen==0){
		if (dhcp_init_state==0) return(0); // do nothing if we're not initing
		// first time that this function is called:
		if (dhcp_init_state==1){
			dhcp_init_state++;
			dhcp_cnt_down=4;
			// Reception of broadcast packets is turned off by default, but
			// the DHCP offer message that the DHCP server sends will be
			// a broadcast packet. Enable here and disable later.
			enc28j60EnableBroadcast();
			send_dhcp_discover(buf,dhcp_tid);
			return(0);
		}
		// still no IP after 4, 8, 16, 32, 64, 128, 4, 8 etc. seconds:
		if (dhcp_yiaddr[0]==0 && dhcp_cnt_down == 0){
			dhcp_tid++;
			dhcp_init_state++;
			if (dhcp_init_state>5) dhcp_init_state=2;
			dhcp_cnt_down=1<<dhcp_init_state;
			// Reception of broadcast packets is turned off by default, but
			// the DHCP offer message that the DHCP server sends will be
			// a broadcast packet. Enable here and disable later.
			enc28j60EnableBroadcast();
			send_dhcp_discover(buf,dhcp_tid);
			return(0);
		}
		return(0);
	}
	// plen > 0
	if (is_dhcp_msg_for_me(buf,plen,dhcp_tid)){
		// It's really a corner case that we check the dhcp_renew_tid
		if (dhcp_is_renew_tid(buf,plen)==1) return(0); // should have been initial tid, just return
		cmd=dhcp_get_message_type(buf,plen);
		if (cmd==2){ // DHCPOFFER =2
			dhcp_init_state=0; // no more init needed
			dhcp_get_yiaddr(buf,plen);
			dhcp_option_parser(buf,plen);
			// answer offer with a request:
			send_dhcp_request(buf,dhcp_tid);
		}
		if (cmd==5){ // DHCPACK =5
			// success, DHCPACK, we have the IP
			dhcp_init_state=0; // no more init needed
			enc28j60DisableBroadcast();
			return(1);
		}
	}
	return(0);
}

// call this to get the current IP 
// returns {0,0,0,0} in assigend_yiaddr if called before we have a valid IP been offered
// otherwise returns back the IP address (4bytes) in assigend_yiaddr.
// assigend_netmask will hold the netmask and assigend_gw the default gateway
// You can fill fields that you don't want (not interested in) to NULL
void dhcp_get_my_ip(uint8_t *assigend_yiaddr,uint8_t *assigend_netmask, uint8_t *assigend_gw, uint8_t *assigend_dns){
	if (assigend_yiaddr) memcpy(assigend_yiaddr,dhcp_yiaddr,4); 
	if (assigend_netmask) memcpy(assigend_netmask,dhcp_opt_mask,4); 
	if (assigend_gw) memcpy(assigend_gw,dhcp_opt_defaultgw,4); 
	if (assigend_dns) memcpy(assigend_dns,dhcp_opt_dns,4); 
}

void dhcp_get_info(uint8_t *server_id,uint32_t *leasetime){
	if (server_id) memcpy(server_id,dhcp_opt_server_id,4);
	if (leasetime) memcpy(leasetime,&dhcp_opt_leasetime,4);
}

// Put the following function into your main packet loop.
// returns plen of original packet if buf is not touched.
// returns 0 if plen was originally zero. returns 0 if DHCP message
// was processed.
// We don't need to expect changing IP addresses. We can stick
// to the IP that we got once. The server has really no power to
// do anything about that.
uint16_t packetloop_dhcp_renewhandler(uint8_t *buf,uint16_t plen){
	if (dhcp_yiaddr[0]==0) return(plen); // do nothing if we don't have a valid IP assigned
	if (plen ==0 && dhcp_cnt_down==0){
		if (!enc28j60linkup()) return(plen); // do nothing if link is down
		dhcp_tid++;
		send_dhcp_renew_request(buf,dhcp_tid,dhcp_yiaddr);
		dhcp_cnt_down=dhcp_opt_leasetime/8; // repeat in 12.5% of lease time if no answer
		return(0);
	}
	if (plen && is_dhcp_msg_for_me(buf,plen,dhcp_tid)){
		if (dhcp_get_message_type(buf,plen)==5){ // DHCPACK =5
			// success, DHCPACK, we have the IP
			// we check the dhcp_renew_tid
			if (dhcp_is_renew_tid(buf,plen)){
				dhcp_option_parser(buf,plen); // get new lease time amongst other
			}
		}
		return(0);
	}
	return(plen);
}


// === end of DHCP client
