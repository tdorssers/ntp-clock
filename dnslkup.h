/*********************************************
 * Author: Guido Socher
 * Copyright:LGPL V2
 * See http://www.gnu.org/licenses/old-licenses/lgpl-2.0.html
 *
 * Modified by: Tim Dorssers
 * Added init_dnslkup()
 *
 * DNS look-up functions based on the udp client
 *********************************************/
//@{
#ifndef DNSLKUP_H
#define DNSLKUP_H 1

// to use this you need to enable UDP_client in the file ip_config.h
//
extern void init_dnslkup(uint8_t *mydns);
// look-up a hostname. returns(0) if the link is up and a dns query was sent out
// otherwise returns 1.
// gwmac is the internal mac addess of your router, you get it with get_mac_with_arp()
extern uint8_t dnslkup_request(uint8_t *buf,const char *hostname,const uint8_t *gwmac);
//
// returns 1 if we have an answer from an DNS server and an IP
extern uint8_t dnslkup_haveanswer(void);
// get information about any error (zero means no error, otherwise see dnslkup.c)
extern uint8_t dnslkup_get_error_info(void);
// loop over this function to search for the answer of the
// DNS server.
// You call this function when enc28j60PacketReceive returned non
// zero and packetloop_icmp_tcp did return zero.
uint8_t udp_client_check_for_dns_answer(uint8_t *buf,uint16_t plen);
// returns the host IP of the name that we looked up if dnslkup_haveanswer did return 1
// ip is the return value
extern void dnslkup_get_ip(uint8_t *ip);
// Determine if the string is a hostname or an IP address
// A valid IP is e.g. "10.10.11.22"
extern uint8_t string_is_ipv4(const char *str);

#endif /* DNSLKUP_H */
//@}
