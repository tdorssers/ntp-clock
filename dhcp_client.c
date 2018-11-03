/*********************************************
 * Author: Guido Socher
 * Copyright:LGPL V2
 * See http://www.gnu.org/licenses/old-licenses/lgpl-2.0.html
 *
 * Modified by: Tim Dorssers
 * - Made several optimizations in terms of code size throughout the DHCP client code,
 *   including replacing 3 while loops in make_dhcp_message_template() by memset to save 6
 *   bytes of code
 * - Improved lease time precision to one second ticks
 * - Added support for lease times longer then one day, including infinity
 * - Changed renewal to start at 50% of lease time
 * - Added support for DNS option parameter (DNS defaults to 8.8.8.8)
 * - Implemented most of the RFC suggested DHCP client state machine for a more robust client
 * - Added support for DHCPNAK message
 * - Changed packetloop_dhcp_initial_ip_assignment() to retransmit at exponential increasing
 *   intervals and removed initial delay, to better meet the RFC
 * - Changed packetloop_dhcp_renewhandler() to retry at intervals of 12.5% of lease time and
 *   enabled broadcast reception
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
static uint8_t dhcp_retry;
static uint8_t dhcp_state=0; // 0 = init, 1 = selecting, 2 = requesting, 3 = bound, 4 = rebinding
const char PROGMEM param_req_lst_end_of_opt[7]={0x37,0x3,0x1,0x3,0x6,0xff,0x0}; // 55, len, subnet mask option, router option, dns option, end of options, 0
const char PROGMEM cookie[4]={0x63,0x82,0x53,0x63};

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
void make_dhcp_message_template(uint8_t *buf)
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
	// we use only one byte TIDs
	while(i<4){
		buf[UDP_DATA_P+i+4]=dhcp_tid;
		i++;
	}
	// set my own MAC the rest is empty:
	memset(buf+UDP_DATA_P+8,0,20);
	// own mac (send_udp_prepare did fill it at eth level):
	memcpy(buf+UDP_DATA_P+28,buf+ETH_SRC_MAC,6);
	// now we need to write 202 bytes of zero
	memset(buf+UDP_DATA_P+34,0,202);
	// DHCP magic cookie
	memcpy_P(buf+UDP_DATA_P+MAGIC_COOKIE_P,cookie,4);
}

// the answer to this message will come as a broadcast
uint8_t send_dhcp_discover(uint8_t *buf)
{
	make_dhcp_message_template(buf);
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

// this will as well update dhcp_yiaddr
uint8_t is_dhcp_msg_for_me(uint8_t *buf,uint16_t plen)
{
	uint8_t i=0;
	// the smallest option is 3 bytes
	if (plen<(UDP_DATA_P+DHCP_OPTION_OFFSET+3)) return(0);
	if (buf[UDP_SRC_PORT_L_P] != DHCP_SRV_SRC_PORT) return(0);
	if (buf[UDP_DATA_P]!=2) return(0); // message type DHCP boot reply =2
	// verify TID:
	while (i<4) {
		if (buf[UDP_DATA_P+4+i]!=dhcp_tid) return(0);
		i++;
	}
	if (buf[UDP_DATA_P+16]!=0){
		// we have a yiaddr
		memcpy(dhcp_yiaddr, buf+UDP_DATA_P+16, 4);
	}
	return(1);
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
static uint8_t send_dhcp_request(uint8_t *buf)
{
	uint8_t i;
	make_dhcp_message_template(buf);
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
// We actually implement REBINDING, not RENEWING, so reception of broadcast
// packets should be turned on.
static uint8_t send_dhcp_renew_request(uint8_t *buf)
{
	make_dhcp_message_template(buf);
	// source IP must be my IP since we renew
	memcpy(buf+IP_SRC_P, dhcp_yiaddr, 4); // ip level source IP
	//
	memcpy(buf+UDP_DATA_P+12,dhcp_yiaddr, 4); // ciaddr
	// option dhcp message type:
	buf[UDP_DATA_P+DHCP_OPTION_OFFSET]=0x35; // 53
	buf[UDP_DATA_P+DHCP_OPTION_OFFSET+1]=1; //len
	buf[UDP_DATA_P+DHCP_OPTION_OFFSET+2]=DHCP_REQUEST_V;
	// no option parameter request list is needed at renew
	send_udp_transmit(buf,DHCP_OPTION_OFFSET+3);
	return(0);
}

// Initial_tid can be a random number for every board, but must be unique.
// E.g the last digit of the MAC address. We rely on unique TIDs in the LAN,
// because we do not check chaddr for a bootp reply.
void init_dhcp(uint8_t initial_tid) {
	dhcp_state=0;
	dhcp_tid=initial_tid;
}

uint8_t is_dhcp_cnt_down_zero(void) {
	return(dhcp_cnt_down==0);
}

// set count down timer to specified divisor of lease time
void set_dhcp_renew_timer(uint8_t divisor) {
	dhcp_cnt_down=dhcp_opt_leasetime/divisor;
	if (is_dhcp_cnt_down_zero()) {
		// quotient is zero, reinitialize:
		dhcp_state=0;
	}
}

// set count down timer to exponential back-off value
void set_dhcp_retry_timer(void) {
	dhcp_cnt_down=dhcp_retry;
}

// init_dhcp() must be called before calling this function in your packetloop.
// The function returns 1 once we have a valid IP. 
uint8_t packetloop_dhcp_initial_ip_assignment(uint8_t *buf,uint16_t plen){
	uint8_t cmd;
	if (!enc28j60linkup()) return(0); // do nothing if the link is down
	if (dhcp_state>2) return(0); // do nothing if we have an IP assigned
	if (plen==0){
		// first time the function is called:
		if (dhcp_state==0){
			dhcp_state=1;
			dhcp_retry=4;
			set_dhcp_retry_timer();
			// Reception of broadcast packets is turned off by default, but
			// the DHCP offer message that the DHCP server sends will be
			// a broadcast packet. Enable here and disable later.
			enc28j60EnableBroadcast();
			send_dhcp_discover(buf);
			return(0);
		}
		// selecting and requesting
		if (dhcp_state && is_dhcp_cnt_down_zero()){
			dhcp_tid++;
			dhcp_retry<<=1; // retry in 4, 8, 16 and 32 seconds
			if (dhcp_retry>32){
				// give up after 60 seconds, reinitialize:
				dhcp_state=0;
				return(0);
			}
			set_dhcp_retry_timer();
			// selecting:
			if (dhcp_state==1){
				send_dhcp_discover(buf);
				return(0);
			}
			// dhcp_state==2, requesting:
			send_dhcp_request(buf);
		}
		return(0);
	}
	// plen > 0
	if (is_dhcp_msg_for_me(buf,plen)){
		cmd=dhcp_get_message_type(buf,plen);
		if (cmd==2){ // DHCPOFFER =2
			dhcp_state=2;
			// resend after 4 seconds
			dhcp_retry=4;
			set_dhcp_retry_timer();
			// parse offer:
			dhcp_option_parser(buf,plen);
			// answer offer with a request:
			send_dhcp_request(buf);
		}
		if (cmd==5){ // DHCPACK =5
			// success, we have the IP
			dhcp_state=3;
			dhcp_retry=0;
			set_dhcp_renew_timer(2); // renew after 50% of lease time
			enc28j60DisableBroadcast();
			return(1);
		}
		if (cmd==6){ // DHCPNAK =6
			dhcp_state=0;
		}
	}
	return(0);
}

// call this to get the current IP 
// returns {0,0,0,0} in assigend_yiaddr if called before we have a valid IP been offered
// otherwise returns back the IP address (4bytes) in assigend_yiaddr.
// assigend_netmask will hold the net mask and assigend_gw the default gateway
// You can fill fields that you don't want (not interested in) to NULL
void dhcp_get_my_ip(uint8_t *assigend_yiaddr,uint8_t *assigend_netmask, uint8_t *assigend_gw, uint8_t *assigend_dns){
	if (assigend_yiaddr) memcpy(assigend_yiaddr,dhcp_yiaddr,4); 
	if (assigend_netmask) memcpy(assigend_netmask,dhcp_opt_mask,4); 
	if (assigend_gw) memcpy(assigend_gw,dhcp_opt_defaultgw,4); 
	if (assigend_dns) memcpy(assigend_dns,dhcp_opt_dns,4); 
}

// Call this to get additional info
// You can fill fields that you don't want (not interested in) to NULL
// Returns DHCP client state
uint8_t dhcp_get_info(uint8_t *server_id,uint32_t *leasetime){
	if (server_id) memcpy(server_id,dhcp_opt_server_id,4);
	if (leasetime) memcpy(leasetime,&dhcp_opt_leasetime,4);
	return(dhcp_state);
}

// Put the following function into your main packet loop.
// returns plen of original packet if buf is not touched.
// returns 0 if plen was originally zero. returns 0 if DHCP message
// was processed.
uint16_t packetloop_dhcp_renewhandler(uint8_t *buf,uint16_t plen){
	uint8_t cmd;
	if (dhcp_state<3) return(plen); // do nothing if we don't have a valid IP assigned
	// check count down timer:
	if (plen ==0 && is_dhcp_cnt_down_zero()){
		if (!enc28j60linkup()) return(plen); // do nothing if link is down
		dhcp_tid++;
		dhcp_state=4;
		enc28j60EnableBroadcast();
		send_dhcp_renew_request(buf);
		set_dhcp_renew_timer(8); // repeat in 12.5% of lease time if no answer
		if (++dhcp_retry>3){
			// 100% of lease time passed, reinitialize:
			dhcp_state=0;
		}
		return(0);
	}
	if (is_dhcp_msg_for_me(buf,plen)){
		cmd=dhcp_get_message_type(buf,plen);
		if (cmd==5){ // DHCPACK =5
			// success, we have the IP
			dhcp_state=3;
			dhcp_retry=0;
			enc28j60DisableBroadcast();
			dhcp_option_parser(buf,plen); // get new lease time amongst other
			set_dhcp_renew_timer(2); // renew after 50% of lease time
		}
		if (cmd==6){ // DHCPNAK =6
			// fail, reinitialize:
			dhcp_state=0;
		}
		return(0);
	}
	return(plen);
}


// === end of DHCP client
