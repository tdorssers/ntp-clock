/*********************************************
 * Author: Guido Socher 
 * Copyright: GPL V2
 *
 * This file can be used to decide which functionallity of the
 * TCP/IP stack shall be available.
 *
 *********************************************/
//@{
#ifndef IP_CONFIG_H
#define IP_CONFIG_H

//------------- functions in ip_arp_udp_tcp.c --------------
// an NTP client (ntp clock):
#define NTP_client

// a spontanious sending UDP client (needed as well for DNS and DHCP)
#define UDP_client

// define this if you want to use enc28j60EnableBroadcast/enc28j60DisableBroadcast
// the dhcp_client.c needs this.
#define ENC28J60_BROADCAST

// a web server
#define WWW_server

// to send out a ping:
#undef PING_client
#define PINGPATTERN 0x42

// a UDP wake on lan sender:
#undef WOL_client

// a "web browser". This can be use to upload data
// to a web server on the internet by encoding the data 
// into the url (like a Form action of type GET):
//#define WWW_client
// if you do not need a browser and just a server:
#undef WWW_client

// modbus requests
#undef TCP_client
//
//------------- functions in websrv_help_functions.c --------------
//
// functions to decode cgi-form data:
#define FROMDECODE_websrv_help

// function to encode a URL (mostly needed for a web client)
#define URLENCODE_websrv_help

#endif /* IP_CONFIG_H */
//@}
