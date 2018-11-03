/*********************************************
 * Author: Guido Socher 
 * Copyright:LGPL V2
 * See http://www.gnu.org/licenses/old-licenses/lgpl-2.0.html
 *
 * Modified by: Tim Dorssers
 * - Added dhcp_get_info()
 * - Added init_dhcp()
 * - Added dhcp_tick()
 * - Removed dhcp_6sec_tick()
 *
 * DHCP client functions
 * This code uses the UDP_client framework. You need to enable UDP_client in ip_config.h to use this.
 *
 * Chip type	   : ATMEGA88/168/328/644 with ENC28J60
 *********************************************/
//@{
#ifndef DHCP_CLIENT_H
#define DHCP_CLIENT_H 1

// enc28j60EnableBroadcast/enc28j60DisableBroadcast is needed 
//
// Initial_tid can be a random number for every board. E.g the last digit
// of the mac address. It is not so important that the number is random.
// It is more important that it is unique and no other board on the same
// LAN has the same number. This is because there might be a power outage
// and all boards reboot afterwards at the same time. At that moment they
// must all have different TIDs otherwise there will be an IP address mess-up.
extern void init_dhcp(uint8_t initial_tid);
// Lease time renewal and time keeping.
// you must call this function every second. It is save
// to do this from interrupt
extern void dhcp_tick(void);
// The function returns 1 once we have a valid IP. 
extern uint8_t packetloop_dhcp_initial_ip_assignment(uint8_t *buf,uint16_t plen);
// get IP, net mask and GW after a successful DHCP offer.
// You can set the parameters that you don't need to NULL (e.g a server will only need the IP).
extern void dhcp_get_my_ip(uint8_t *assigend_yiaddr,uint8_t *assigend_netmask, uint8_t *assigend_gw, uint8_t *assigend_dns);
// Put the following function into your main packet loop.
// returns plen of original packet if buf is not touched.
// returns 0 if plen was originally zero. returns 0 if DHCP messages
// was processed.
extern uint16_t packetloop_dhcp_renewhandler(uint8_t *buf,uint16_t plen);
// Call this to get additional info
// You can fill fields that you don't want (not interested in) to NULL
// Returns DHCP client state
extern uint8_t dhcp_get_info(uint8_t *server_id,uint32_t *leasetime);

#endif /* DHCP_CLIENT_H */
//@}
