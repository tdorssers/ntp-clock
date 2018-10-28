/*********************************************
 * Author: Tim Dorssers
 *
 * This software implements a NTP synchronized clock with two classic HDLX2416
 * LED matrix displays and a DHT11 temperature and humidity sensor. Dynamic IP
 * address assignment is done using DHCP. DNS lookup is used for NTP host name
 * resolution. It is configurable via a built-in web server that implements GET
 * and POST methods and HTTP basic authentication. Web configurable parameters
 * are stored in EEPROM. At Ethernet link up, an IP address is obtained and
 * displayed for 30 seconds in which ARP, DNS and NTP are executed. If one of
 * those fails, the clock is reinitialized after that time. The modified DHCP
 * client retries obtaining the initial IP at exponential increasing intervals
 * and renews the address lease at half lease time, at 12.5% of the lease time
 * increasing intervals. Standard AVR Libc time keeping functions are used.
 * The highest and lowest temperature and humidity is recorded in RAM with time
 * stamps. Useful log messages are sent to the UART.
 *
 * It uses a modified version of Guido Socher's TCP/IP stack, with changes to:
 * - enc28j60.c
 * - dhcp_client.c
 * - dnslkup.c
 * - websrv_help_functions.c
 *
 * You need to define F_CPU as a symbol to gcc eg. -DF_CPU=7372800
 *
 * Copyright: GPL V2
 * See http://www.gnu.org/licenses/gpl.html
 *
 * Chip type	   : Atmega328 with ENC28J60
 *********************************************/
#include <avr/io.h>
#include <avr/interrupt.h>
#include <avr/pgmspace.h>
#include <avr/eeprom.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include "ip_arp_udp_tcp.h"
#include "websrv_help_functions.h"
#include "enc28j60.h"
#include "dhcp_client.h"
#include "dnslkup.h"
#include "hdlx2416.h"
#include "uart.h"
#include "dht.h"

// Board MAC address
static uint8_t mymac[6] = {0x54,0x10,0xEC,0x00,0x28,0x60};
// Time zone in minutes offset to UTC
int16_t mins_offset_to_utc = 60;
// Enable daylight saving time for EU
static uint8_t enable_eu_dst = 1;
// NTP Host name
#define HOSTNAME_SIZE 24
static char ntphostname[HOSTNAME_SIZE+1] = "time.apple.com";
// Config web page password
#define PASSWORD_SIZE 16
static char password[PASSWORD_SIZE+1] = "secret";
// NTP Update period in seconds
static uint16_t ntp_update_period = 3600;
// NTP IP (DNS will provide a value for it):
static uint8_t ntpip[4];
// DNS (DHCP will provide a value for it):
static uint8_t mydns[4];
// My own IP (DHCP will provide a value for it):
static uint8_t myip[4];
// Default gateway (DHCP will provide a value for it):
static uint8_t gwip[4];
// Net mask (DHCP will provide a value for it):
static uint8_t netmask[4];
// ARP resolving:
#define TRANS_NUM_NTPMAC 1
#define TRANS_NUM_DNSMAC 2
static uint8_t ntproutingmac[6];
static uint8_t dnsroutingmac[6];
// state vars:
static uint8_t have_ntp_mac=0;
static uint8_t have_dns_mac=0;
static int8_t init_state=-1; // 0=link up, 1=initial IP assignment, 2=resolve arps, 3=dns lookup, 4=ready for ntp req, 5=running
static uint8_t dns_state=0;
// global string buffer
#define STR_BUFFER_SIZE 32
static char gStrbuf[STR_BUFFER_SIZE+1];
// NTP:
static uint8_t ntpclientportL; // lower 8 bytes of local port number
static uint8_t haveNTPanswer=0; // 0=never sent a ntp req, 1=have time, 2=request sent no answer yet
static uint8_t ntp_retry_count=0;
static time_t start_t; // time of last ntp update
static uint8_t display_24hclock=1;
// timer:
static volatile uint8_t display_update_pending=0;
static volatile uint8_t delay_sec=0;
static volatile uint8_t dht_delay_sec=0;
static volatile uint8_t uptime_sec=0;
static volatile uint8_t uptime_min=0;
static volatile uint8_t uptime_hour=0;
static volatile uint16_t uptime_day=0;
// eth/ip buffer:
#define BUFFER_SIZE 808
static uint8_t buf[BUFFER_SIZE+1];
static uint16_t dat_p;
// Display:
static uint8_t intensity=4;
const char PROGMEM intensity0[]={">100%"};
const char PROGMEM intensity1[]={">60%"};
const char PROGMEM intensity2[]={">40%"};
const char PROGMEM intensity3[]={">27%"};
const char PROGMEM intensity4[]={">17%"};
const char PROGMEM intensity5[]={">10%"};
const char PROGMEM intensity6[]={">7%"};
const char PROGMEM intensity7[]={">3%"};
PGM_P const PROGMEM intensities[8]={intensity0,intensity1,intensity2,intensity3,intensity4,intensity5,intensity6,intensity7};
// DHT:
static uint8_t display_temperature=1;
static int8_t temperature;
static int8_t humidity;
static time_t low_temp_t;
static time_t high_temp_t;
static time_t low_hum_t;
static time_t high_hum_t;
static int8_t low_temp=127;
static int8_t low_hum=127;
static int8_t high_temp=0;
static int8_t high_hum=0;
// EEPROM:
uint8_t EEMEM nv_magic_number_config;
uint8_t EEMEM nv_ntpip[4];
uint8_t EEMEM nv_password[PASSWORD_SIZE+1];
uint8_t EEMEM nv_enable_eu_dst;
uint8_t EEMEM nv_display_24hclock;
uint16_t EEMEM nv_mins_offset_to_utc;
uint8_t EEMEM nv_ntphostname[HOSTNAME_SIZE+1];
uint8_t EEMEM nv_mymac[6];
uint8_t EEMEM nv_magic_number_display;
uint8_t EEMEM nv_display_temperature;
uint8_t EEMEM nv_intensity;
uint16_t EEMEM nv_ntp_update_period;
uint8_t EEMEM nv_magic_number_password;

// Daylight Saving function for the European Union
// From http://savannah.nongnu.org/bugs/?44327
static int eu_dst(const time_t *timer, int32_t *z)
{
	uint32_t t = *timer;
	if ((uint8_t)(t >> 24) >= 194) t -= 3029443200U;
	t = (t + 655513200) / 604800 * 28;
	if ((uint16_t)(t % 1461) < 856) return 3600;
	else return 0;
}

// convert two decimal number to string with leading zero
// s must point a 3 bytes buffer minimum
static void zero_two_d(char *s, uint8_t v) {
	if (v > 99) return;
	if (v < 10) *s++ = '0';
	itoa(v, s, 10);
}

// convert utc offset in minutes to string
// buf must point a 7 bytes buffer minimum
static void offset_to_dispstr(int16_t min_offset, char *buf) {
	uint8_t min, hour;
	
	if (min_offset < 0) {
		buf[0] = '-';
		min_offset = -min_offset;
	} else {
		buf[0] = '+';
	}
	min = min_offset % 60;
	hour = min_offset / 60;
	zero_two_d(buf + 1, hour);
	buf[3] = ':';
	zero_two_d(buf + 4, min);
}

// parse utc offset string to offset
// returns offset in minutes
static int16_t parse_offset(char *buf) {
	int16_t min_offset;
	int8_t hour;
	uint8_t min = 0;
	char *sep;
	
	hour = atoi(buf);
	if ((sep = strchr(buf, ':'))) {
		*sep++ = '\0';
		min = atoi(sep);
	}
	min_offset = hour * 60;
	if (hour < 0) {
		min_offset -= min;
	} else {
		min_offset += min;
	}
	return min_offset;
}

// 62 bytes
static uint16_t http200ok(void){
	return(fill_tcp_data_p(buf,0,PSTR("HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nPragma: no-cache\r\n\r\n")));
}

// 59 bytes
static uint16_t http200okjs(void){
	return(fill_tcp_data_p(buf,0,PSTR("HTTP/1.0 200 OK\r\nContent-Type: application/x-javascript\r\n\r\n")));
}

// 43 bytes
static uint16_t http200okcss(void){
	return(fill_tcp_data_p(buf,0,PSTR("HTTP/1.0 200 OK\r\nContent-Type: text/css\r\n\r\n")));
}

// 47 bytes
static uint16_t http302moved(void){
	return(fill_tcp_data_p(buf,0,PSTR("HTTP/1.0 302 Moved Temporarily\r\nLocation: /\r\n\r\n")));
}

// 95 bytes
static uint16_t http401unauth(void){
	return(fill_tcp_data_p(buf,0,PSTR("HTTP/1.0 401 Unauthorized\r\nContent-Type: text/html\r\nWWW-Authenticate: Basic realm=NTP clock\r\n\r\n")));
}

// 51 bytes
static uint16_t http404notfound(void){
	return(fill_tcp_data_p(buf,0,PSTR("HTTP/1.0 404 Not Found\r\nContent-Type: text/html\r\n\r\n")));
}

// 63 bytes
static uint16_t http500interr(void){
	return(fill_tcp_data_p(buf,0,PSTR("HTTP/1.0 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\n")));
}

// 57 bytes
static uint16_t http501notimpl(void){
	return(fill_tcp_data_p(buf,0,PSTR("HTTP/1.0 501 Not Implemented\r\nContent-Type: text/html\r\n\r\n")));
}

// tz.js
static uint16_t print_tzjs(void)
{
	uint16_t plen;
	plen=http200okjs();
	// show this computers TZ offset
	plen=fill_tcp_data_p(buf,plen,PSTR("\
function tzi(){\n\
	var d = new Date();\n\
	var tzo = -d.getTimezoneOffset();\n\
	var rem = tzo % 60;\n\
	var min = (\"0\" + rem).slice(-2);\n\
	var hour = (\"0\" + (tzo - rem) / 60).slice(-2);\n\
	var st = hour + \":\" + min;\n\
	if (tzo > 0) st = \"UTC+\" + st; else st = \"UTC\" + st;\n\
	document.write(\" [Info: your PC is \"+st+\"]\");\n\
}\n"));
	return(plen);
}

// s.css
static uint16_t print_s1css(void) {
	uint16_t plen;
	
	plen=http200okcss();
	plen=fill_tcp_data_p(buf,plen,PSTR("\
body {\n\
	font-family: arial, sans-serif;\n\
}\n\
h2 {\n\
	background: #4caf50;\n\
	padding: 4px;\n\
	color: #fff;\n\
}\n\
pre {\n\
	border: 1px solid #ddd;\n\
	padding: 8px;\n\
}\n\
div {\n\
	width: 550px;\n\
	border: 2px solid;\n\
	margin: 10px auto;\n\
	padding: 0 20px 10px 20px;\n\
}\n\
a {\n\
	text-decoration: none;\n\
}\n\
a:hover {\n\
	text-decoration: underline;\n\
}\n"));
	return(plen);
}

// returns netmask length
static uint8_t get_netmask_length(uint8_t *mask){
	uint8_t i,j;
	uint8_t l=0;
	i=0;
	while(i<4){
		j=0;
		while(j<8){
			if (mask[i] & (1<<j)){
				l++;
			}else{
				j=7;i=3;
			}
			j++;
		}
		i++;
	}
	return(l);
}

// prints progmem string followed by a number on the web page to the tcp send buffer
static uint16_t print_number_on_webpage(uint16_t pos, uint16_t num, const char *progmem_s) {
	pos=fill_tcp_data_p(buf,pos,progmem_s);
	utoa(num,gStrbuf,10);
	pos=fill_tcp_data(buf,pos,gStrbuf);
	return(pos);
}

// prints a number followed by a progmem string on the web page to the tcp send buffer
static uint16_t print_number_first_on_webpage(uint16_t pos, uint16_t num, const char *progmem_s) {
	utoa(num,gStrbuf,10);
	pos=fill_tcp_data(buf,pos,gStrbuf);
	pos=fill_tcp_data_p(buf,pos,progmem_s);
	return(pos);
}

// prints progmem string followed by an IP address on the web page to the tcp send buffer
static uint16_t print_ip_on_webpage(uint16_t pos, uint8_t *ip, const char *progmem_s) {
	pos=fill_tcp_data_p(buf,pos,progmem_s);
	mk_net_str(gStrbuf,ip,4,'.',10);
	pos=fill_tcp_data(buf,pos,gStrbuf);
	return(pos);
}

// prints progmem string followed by a MAC address on the web page to the tcp send buffer
static uint16_t print_mac_on_webpage(uint16_t pos, uint8_t *mac, const char *progmem_s) {
	pos=fill_tcp_data_p(buf,pos,progmem_s);
	mk_net_str(gStrbuf,mac,6,':',16);
	pos=fill_tcp_data(buf,pos,gStrbuf);
	return(pos);
}

// prints progmem string followed by a timestamp on the web page to the tcp send buffer
static uint16_t print_time_on_webpage(uint16_t pos, time_t *t, const char *progmem_s) {
	struct tm *ts;
	
	pos=fill_tcp_data_p(buf,pos,progmem_s);
	ts = localtime(t);
	asctime_r(ts, gStrbuf);
	pos=fill_tcp_data(buf,pos,gStrbuf);
	return(pos);
}

// prints the header of a web page with optional progmem string to the tcp send buffer
static uint16_t print_html_head(uint16_t pos,const char *progmem_s) {
	pos=fill_tcp_data_p(buf,pos,PSTR("<!DOCTYPE html>\n<html><head><title>NTP clock</title><link rel=stylesheet href=s.css>"));
	if (progmem_s) pos=fill_tcp_data_p(buf,pos,progmem_s);
	pos=fill_tcp_data_p(buf,pos,PSTR("</head><body><div>"));
	return(pos);
}

// prints the footer of a web page to the tcp send buffer
static uint16_t print_html_foot(uint16_t pos) {
	return(fill_tcp_data_p(buf,pos,PSTR("</div></body></html>")));
}

// prepare the web page by writing the data to the tcp send buffer
static uint16_t print_webpage_ok(void) {
	return(print_html_foot(fill_tcp_data_p(buf,print_html_head(http200ok(),NULL),PSTR("<h2>NTP config</h2><a href=/>OK</a>"))));
}

// prepare the web page by writing the data to the tcp send buffer
static uint16_t print_webpage_error(void) {
	return(print_html_foot(fill_tcp_data_p(buf,print_html_head(http200ok(),NULL),PSTR("<h2>NTP config</h2><a href=/?pg=1>Error</a>"))));
}

// prepare the web page by writing the data to the tcp send buffer
static uint16_t print_webpage_authfail(void) {
	return(print_html_foot(fill_tcp_data_p(buf,print_html_head(http401unauth(),NULL),PSTR("<h2>NTP config</h2><a href=/>Authentication Failure</a>"))));
}

// prepare the web page by writing the data to the tcp send buffer
static uint16_t print_webpage_config(void)
{
	uint16_t plen;
	plen=print_html_head(http200ok(),PSTR("<script src=tz.js></script>"));
	plen=fill_tcp_data_p(buf,plen,PSTR("<h2>NTP config</h2><pre><form action=/cu method=post>\n<b>NTP hostname:</b>\t<input type=text name=nt value="));
	plen=fill_tcp_data(buf,plen,ntphostname);
	plen=print_number_on_webpage(plen,ntp_update_period,PSTR(">\n<b>Update period:</b>\t<input type=text name=up value="));
	plen=print_mac_on_webpage(plen,mymac,PSTR(">\n<b>MAC address:</b>\t<input type=text name=ma value="));
	plen=fill_tcp_data_p(buf,plen,PSTR(">\n<b>UTC offset:</b>\t<input type=text name=tz value="));
	offset_to_dispstr(mins_offset_to_utc,gStrbuf);
	plen=fill_tcp_data(buf,plen,gStrbuf);
	plen=fill_tcp_data_p(buf,plen,PSTR("><script>tzi()</script>\n<b>Apply:</b>\t\t<input type=checkbox name=st"));
	if (enable_eu_dst){
		plen=fill_tcp_data_p(buf,plen,PSTR(" checked"));
	}
	plen=fill_tcp_data_p(buf,plen,PSTR(">EU DST\n<br><input type=submit value=apply> <input type=button value=cancel onclick=\"window.location='/'\"></form></pre>"));
	plen=print_html_foot(plen);
	return(plen);
}

// prepare the web page by writing the data to the tcp send buffer
static uint16_t print_webpage_password(void) {
	uint16_t plen;
	
	plen=print_html_head(http200ok(),NULL);
	plen=fill_tcp_data_p(buf,plen,PSTR("<h2>NTP password</h2><pre><form action=/pu method=post>\n<b>New password:</b>\t<input type=password name=pw>\n<br><input type=submit value=apply> <input type=button value=cancel onclick=\"window.location='/'\"></form></pre>"));
	plen=print_html_foot(plen);
	return(plen);
}

// prepare the web page by writing the data to the tcp send buffer
static uint16_t print_webpage_display(void) {
	uint16_t plen;
	PGM_P ptr;
	uint8_t i;
	
	plen=print_html_head(http200ok(),NULL);
	plen=fill_tcp_data_p(buf,plen,PSTR("<h2>NTP display</h2><pre><form action=/du method=post>\n<b>Show:</b>\t\t<input type=checkbox name=hh"));
	if (display_24hclock){
		plen=fill_tcp_data_p(buf,plen,PSTR(" checked"));
	}
	plen=fill_tcp_data_p(buf,plen,PSTR(">24h <input type=checkbox name=te"));
	if (display_temperature){
		plen=fill_tcp_data_p(buf,plen,PSTR(" checked"));
	}
	plen=fill_tcp_data_p(buf,plen,PSTR(">Temperature\n<b>Intensity:</b>\t<select name=in>"));
	for (i=0;i<8;i++) {
		plen=fill_tcp_data_p(buf,plen,PSTR("<option value="));
		gStrbuf[0]='0'+i;
		gStrbuf[1]='\0';
		plen=fill_tcp_data(buf,plen,gStrbuf);
		if (intensity==i){
			plen=fill_tcp_data_p(buf,plen,PSTR(" selected"));
		}
		memcpy_P(&ptr, &intensities[i], sizeof(PGM_P));
		plen=fill_tcp_data_p(buf,plen,ptr);
		plen=fill_tcp_data_p(buf,plen,PSTR("</option>"));
	}
	plen=fill_tcp_data_p(buf,plen,PSTR("</select>\n<br><input type=submit value=apply> <input type=button value=cancel onclick=\"window.location='/'\"></form></pre>"));
	plen=print_html_foot(plen);
	return(plen);
}

// prepare the web page by writing the data to the tcp send buffer
static uint16_t print_webpage_history(void) {
	uint16_t plen;
	
	plen=print_html_head(http200ok(),NULL);
	plen=fill_tcp_data_p(buf,plen,PSTR("<h2>History</h2><pre><form action=/ method=get>\n"));
	plen=print_number_on_webpage(plen,high_temp,PSTR("<b>Highest Temperature:</b>\t"));
	plen=print_time_on_webpage(plen,&high_temp_t,PSTR(" &deg;C @ "));
	plen=print_number_on_webpage(plen,low_temp,PSTR("\n<b>Lowest Temperature:</b>\t"));
	plen=print_time_on_webpage(plen,&low_temp_t,PSTR(" &deg;C @ "));
	plen=print_number_on_webpage(plen,high_hum,PSTR("\n<b>Highest Humidity:</b>\t"));
	plen=print_time_on_webpage(plen,&high_hum_t,PSTR(" %  @ "));
	plen=print_number_on_webpage(plen,low_hum,PSTR("\n<b>Lowest Humidity:</b>\t"));
	plen=print_time_on_webpage(plen,&low_hum_t,PSTR(" %  @ "));
	plen=fill_tcp_data_p(buf,plen,PSTR("\n<br><input name=pg type=hidden value=3><input name=ac type=submit value=clear></form></pre><a href=/>home</a> | <a href=/?pg=3>refresh</a>"));
	plen=print_html_foot(plen);
	return(plen);
}

// prepare the web page by writing the data to the tcp send buffer
static uint16_t print_webpage_info(void) {
	uint16_t plen;
	uint8_t *gwmac=NULL;
	uint8_t server_id[4];
	uint32_t leasetime;
	time_t now;
	
	plen=print_html_head(http200ok(),NULL);
	plen=print_number_on_webpage(plen,enc28j60getrev(),PSTR("<h2>Info</h2><pre><b>ENC28J60 Rev:</b>\tB"));
	plen=print_mac_on_webpage(plen,mymac,PSTR("\n<b>MAC address:</b>\t"));
	plen=print_ip_on_webpage(plen,myip,PSTR("\n<b>IP address:</b>\t"));
	gStrbuf[0]='/';
	itoa(get_netmask_length(netmask),gStrbuf+1,10);
	plen=fill_tcp_data(buf,plen,gStrbuf);
	plen=print_ip_on_webpage(plen,gwip,PSTR("\n<b>Gateway:</b>\t"));
	if (route_via_gw(ntpip))
		gwmac=&ntproutingmac[0];
	else
		plen=print_mac_on_webpage(plen,ntproutingmac,PSTR("\n<b>NTP MAC:</b>\t"));
	if (route_via_gw(mydns))
		gwmac=&dnsroutingmac[0];
	else
		plen=print_mac_on_webpage(plen,dnsroutingmac,PSTR("\n<b>DNS MAC:</b>\t"));
	if (gwmac)
		plen=print_mac_on_webpage(plen,gwmac,PSTR("\n<b>Gateway MAC:</b>\t"));
	plen=print_number_on_webpage(plen,ntp_update_period,PSTR("\n<b>Update period:</b>\t"));
	dhcp_get_info(server_id,&leasetime);
	plen=print_ip_on_webpage(plen,server_id,PSTR("\n<b>DHCP server:</b>\t"));
	time(&now);
	now+=leasetime;
	plen=print_time_on_webpage(plen,&now,PSTR("\n<b>Lease expires:</b>\t"));
	plen=fill_tcp_data_p(buf,plen,PSTR("\n<b>Uptime:</b>\t\t"));
	if (uptime_day)
		plen=print_number_first_on_webpage(plen,uptime_day,PSTR(" days, "));
	if (uptime_hour)
		plen=print_number_first_on_webpage(plen,uptime_hour,PSTR(" hours, "));
	if (uptime_min)
		plen=print_number_first_on_webpage(plen,uptime_min,PSTR(" minutes, "));
	plen=print_number_first_on_webpage(plen,uptime_sec,PSTR(" seconds\n</pre><a href=/>home</a> | <a href=/?pg=4>refresh</a>"));
	plen=print_html_foot(plen);
	return(plen);
}

// prepare the main web page by writing the data to the tcp send buffer
static uint16_t print_webpage_main(void)
{
	uint16_t plen;
	time_t now;
	plen=print_html_head(http200ok(),NULL);
	time(&now);
	plen=print_time_on_webpage(plen,&now,PSTR("<h2>NTP clock</h2><pre><b>Time:</b>\t\t"));
	plen=fill_tcp_data_p(buf,plen,PSTR(" (UTC"));
	offset_to_dispstr(mins_offset_to_utc,gStrbuf);
	plen=fill_tcp_data(buf,plen,gStrbuf);
	plen=print_ip_on_webpage(plen,mydns,PSTR(")\n<b>DNS server:</b>\t"));
	plen=fill_tcp_data_p(buf,plen,PSTR(" ["));
	if (dnslkup_get_error_info()) 
		plen=fill_tcp_data_p(buf,plen,PSTR("Error"));
	else if (!dnslkup_haveanswer()) 
		plen=fill_tcp_data_p(buf,plen,PSTR("Timeout"));
	else
		plen=fill_tcp_data_p(buf,plen,PSTR("OK"));
	plen=fill_tcp_data_p(buf,plen,PSTR("]\n<b>NTP server:</b>\t"));
	plen=fill_tcp_data(buf,plen,ntphostname);
	plen=print_ip_on_webpage(plen,ntpip,PSTR(" ["));
	plen=print_time_on_webpage(plen,&start_t,PSTR("]\n<b>Last sync:</b>\t"));
	if (haveNTPanswer!=1) 
		plen=fill_tcp_data_p(buf,plen,PSTR(" [Syncing]")); 
	else 
		plen=fill_tcp_data_p(buf,plen,PSTR(" [OK]"));
	plen=print_number_on_webpage(plen,temperature,PSTR("\n<b>Temperature:</b>\t"));
	plen=print_number_on_webpage(plen,humidity,PSTR(" &deg;C\n<b>Humidity:</b>\t"));
	plen=fill_tcp_data_p(buf,plen,PSTR(" %\n</pre><a href=/?pg=1>config</a> | <a href=/?pg=2>display</a> | <a href=/?pg=3>history</a> | <a href=/?pg=4>info</a> | <a href=/?pg=5>password</a> | <a href=/>refresh</a>"));
	plen=print_html_foot(plen);
	return(plen);
}

// parse a string that is a MAC address and extract the MAC to mac_byte_str
// returns 1 if successful or 0 otherwise
static uint8_t parse_mac(uint8_t *mac_byte_str,const char *str)
{
	uint8_t c,b;
	uint8_t i=0;
	while(i<6){
		mac_byte_str[i]=0;
		i++;
	}
	i=0;
	while(*str && i<6){
		if (isxdigit(*str)) {
			c=toupper(*str);
			if (c>'9') c-=7;
			c-='0';
			b=c;
			str++;
			if (isxdigit(*str)) {
				c=toupper(*str);
				if (c>'9') c-=7;
				c-='0';
				b<<=4;
				b|=c;
			}
			mac_byte_str[i++]=b;
		}
		str++;
	}
	if (i==6) return(0);
	return(1);
}

// decodes a base64-encoded string
static void base64_decode(char *str) {
	char *out = str;
	char stream[4];
	while (strlen(str) >= 4) {
		for (uint8_t i = 0; i < 4; ++i) {
			if (*str >= 'A' && *str <= 'Z') {
				stream[i] = *str - 'A';
			}
			else if (*str >= 'a' && *str <= 'z') {
				stream[i] = *str - 'a' + 26;
			}
			else if (*str >= '0' && *str <= '9') {
				stream[i] = *str - '0' + 52;
			}
			else if (*str == '+') {
				stream[i] = 62;
			}
			else if (*str == '/') {
				stream[i] = 63;
			}
			else if (*str == '=') {
				stream[i] = 0;
			}
			++str;
		}
		*out++ = stream[0] << 2 | stream[1] >> 4;
		*out++ = stream[1] << 4 | stream[2] >> 2;
		*out++ = stream[2] << 6 | stream[3] >> 0;
	}
	*out = '\0';
}

// verifies credentials in the given html header
// returns 1 if credentials match, 0 otherwise
static uint8_t check_authorization(char *str) {
	char *auth_str,*pw_str;
	
	if ((auth_str=strstr_P(str,PSTR("Authorization:")))){
		auth_str+=21;
		base64_decode(auth_str);
		pw_str=strchr(auth_str,':');
		*pw_str++='\0';
		if (strncmp(password,pw_str,PASSWORD_SIZE)==0){
			return(1);
		}
	}
	return(0);
}

// analyze the url given
static uint8_t analyse_get_url(char *str)
{
	if (str[0] == '/' && str[1] == ' '){
		// end of url, display just the root web page
		dat_p=print_webpage_main();
		return(0);
	}
	if (str[0] == '/' && str[1] == '?'){
		if (find_key_val_p(str,gStrbuf,STR_BUFFER_SIZE,PSTR("ac"))){
			low_temp_t=high_temp_t=low_hum_t=high_hum_t=0;
			low_hum=low_temp=127;
			high_hum=high_temp=0;
		}
		if (find_key_val_p(str,gStrbuf,STR_BUFFER_SIZE,PSTR("pg"))){
			urldecode(gStrbuf);
			switch (atoi(gStrbuf)) {
				case 1:
					if (check_authorization(str)) {
						dat_p=print_webpage_config();
					} else {
						dat_p=print_webpage_authfail();
					}
					return(0);
				case 2:
					dat_p=print_webpage_display();
					return(0);
				case 3:
					dat_p=print_webpage_history();
					return(0);
				case 4:
					dat_p=print_webpage_info();
					return(0);
				case 5:
					if (check_authorization(str)) {
						dat_p=print_webpage_password();
					} else {
						dat_p=print_webpage_authfail();
					}
					return(0);
			}
		}
	}
	if (strncmp_P(str,PSTR("/tz.js"),6)==0){
		dat_p=print_tzjs();
		return(0);
	}
	if (strncmp_P(str,PSTR("/s.css"),6)==0){
		dat_p=print_s1css();
		return(0);
	}
	dat_p=http404notfound();
	return(0);
}

// analyze the body of the given html document
static uint8_t analyse_post_url(char *str) {
	char *body;
	int16_t i=0;
	uint8_t updateerr=0;
	
	if ((body=strstr_P(str,PSTR("\r\n\r\n")))) {
		body+=4;
		uart_puts(body);
		uart_puts_P("\r\n");
		if (strncmp_P(str,PSTR("/pu"),3)==0){
			if (find_key_val_p(body,gStrbuf,STR_BUFFER_SIZE,PSTR("pw"))){
				urldecode(gStrbuf);
				strncpy(password,gStrbuf,PASSWORD_SIZE);
				password[PASSWORD_SIZE]='\0';
				// store in eeprom:
				eeprom_write_byte(&nv_magic_number_password,0x33); // magic number
				eeprom_write_block(&password,&nv_password,sizeof(password));
				//dat_p=print_webpage_main();
				dat_p=http302moved();
				return(0);
			}
		}
		if (strncmp_P(str,PSTR("/du"),3)==0){
			display_24hclock=0;
			if (find_key_val_p(body,gStrbuf,STR_BUFFER_SIZE,PSTR("hh"))){
				display_24hclock=1;
			}
			display_temperature=0;
			if (find_key_val_p(body,gStrbuf,STR_BUFFER_SIZE,PSTR("te"))){
				display_temperature=1;
			}
			if (find_key_val_p(body,gStrbuf,STR_BUFFER_SIZE,PSTR("in"))){
				urldecode(gStrbuf);
				intensity=atoi(gStrbuf);
				hdlx2416_intensity(intensity);
			}
			// store in eeprom:
			eeprom_write_byte(&nv_magic_number_display,0xAA); // magic number
			eeprom_write_byte(&nv_display_24hclock,display_24hclock);
			eeprom_write_byte(&nv_display_temperature,display_temperature);
			eeprom_write_byte(&nv_intensity,intensity);
			//dat_p=print_webpage_main();
			dat_p=http302moved();
			return(0);
		}
		if (strncmp_P(str,PSTR("/cu"),3)==0){
			if (find_key_val_p(body,gStrbuf,STR_BUFFER_SIZE,PSTR("ma"))){
				urldecode(gStrbuf);
				if (parse_mac(mymac,gStrbuf)!=0){
					updateerr=1;
				}
			}
			if (find_key_val_p(body,gStrbuf,STR_BUFFER_SIZE,PSTR("nt"))){
				urldecode(gStrbuf);
				strncpy(ntphostname, gStrbuf,HOSTNAME_SIZE);
				ntphostname[HOSTNAME_SIZE]='\0';
				if (strlen(gStrbuf)>HOSTNAME_SIZE) {
					updateerr=1;
				}
			}
			if (find_key_val_p(body,gStrbuf,STR_BUFFER_SIZE,PSTR("up"))){
				urldecode(gStrbuf);
				ntp_update_period=atoi(gStrbuf);
			}
			enable_eu_dst=0;
			set_dst(NULL);
			if (find_key_val_p(body,gStrbuf,STR_BUFFER_SIZE,PSTR("st"))){
				enable_eu_dst=1;
				set_dst(eu_dst);
			}
			if (find_key_val_p(body,gStrbuf,STR_BUFFER_SIZE,PSTR("tz"))){
				urldecode(gStrbuf);
				i=parse_offset(gStrbuf);
				if (i>=-720 && i<=840){
					mins_offset_to_utc=i;
					set_zone((int32_t)mins_offset_to_utc * 60);
					}else{
					updateerr=1;
				}
			}
			if (updateerr){
				dat_p=print_webpage_error();
				return(0);
			}
			// store in eeprom:
			eeprom_write_byte(&nv_magic_number_config,0x55); // magic number
			eeprom_write_block(&ntpip,&nv_ntpip,sizeof(ntpip));
			eeprom_write_byte(&nv_enable_eu_dst,enable_eu_dst);
			eeprom_write_word(&nv_mins_offset_to_utc,mins_offset_to_utc);
			eeprom_write_block(&ntphostname,&nv_ntphostname,sizeof(ntphostname));
			eeprom_write_block(&mymac,&nv_mymac,sizeof(mymac));
			eeprom_write_word(&nv_ntp_update_period,ntp_update_period);
			dat_p=print_webpage_ok();
			return(1);
		}
	}
	dat_p=http500interr();
	return(0);
}

// prints timestamp with offset to utc to uart
static void print_time_to_uart(void) {
	time_t now;
	struct tm *ts;

	time(&now);
	ts = localtime(&now);
	asctime_r(ts, gStrbuf);
	uart_puts(gStrbuf);
	uart_puts_P(" (UTC");
	offset_to_dispstr(mins_offset_to_utc,gStrbuf);
	uart_puts(gStrbuf);
	uart_puts_P(")\r\n");
}

// prints ip, netmask and dns to uart
static void print_ip_to_uart(void) {
	mk_net_str(gStrbuf,myip,4,'.',10);
	uart_puts_P("Got IP:");
	uart_puts(gStrbuf);
	uart_putc('/');
	itoa(get_netmask_length(netmask),gStrbuf,10);
	uart_puts(gStrbuf);
	uart_puts_P("\r\n");
	mk_net_str(gStrbuf,mydns,4,'.',10);
	uart_puts_P("DNS IP:");
	uart_puts(gStrbuf);
	uart_puts_P("\r\n");
}

// prints enc28j60 silicon revision to uart
static void print_rev_to_uart(void) {
	itoa(enc28j60getrev(),gStrbuf,10);
	uart_puts_P("ENC28J60 Rev B");
	uart_puts(gStrbuf);
	uart_puts_P("\r\n");	
}

// prints temperature and humidity to display
static void print_dht_to_display(void) {
	hdlx2416_goto(0);
	itoa(temperature,gStrbuf,10);
	hdlx2416_puts(gStrbuf);
	hdlx2416_puts_P("'C ");
	itoa(humidity,gStrbuf,10);
	hdlx2416_puts(gStrbuf);
	hdlx2416_putc('%');
}

// prints timestamp to display and checks if the ntp update period has passed
static void print_time_to_display(void)
{
	time_t now;
	struct tm *ts;
	uint8_t hour;

	time(&now);
	ts = localtime(&now);
	hdlx2416_goto(0);
	hour = ts->tm_hour;
	if (display_24hclock == 0 && hour > 12) {
		hour -= 12;
	}
	itoa(hour,gStrbuf,10);
	if (strlen(gStrbuf)==1) {
		hdlx2416_putc('0');
	}
	hdlx2416_puts(gStrbuf);
	// blink colon
	if (display_24hclock == 0 && ts->tm_sec % 2) {
		hdlx2416_putc(' ');
	} else {
		hdlx2416_putc(':');
	}
	itoa(ts->tm_min,gStrbuf,10);
	if (strlen(gStrbuf)==1) {
		hdlx2416_putc('0');
	}
	hdlx2416_puts(gStrbuf);
	if (display_24hclock==0) {
		if (ts->tm_hour < 12) {
			hdlx2416_puts_P("am ");
		} else {
			hdlx2416_puts_P("pm ");
		}
	} else {
		hdlx2416_putc(':');
		itoa(ts->tm_sec,gStrbuf,10);
		if (strlen(gStrbuf)==1) {
			hdlx2416_putc('0');
		}
		hdlx2416_puts(gStrbuf);
	}
	if (difftime(now, start_t)>ntp_update_period && haveNTPanswer==1){
		// mark that we will wait for new ntp update
		haveNTPanswer=2;
		ntp_retry_count=0;
	}
}

// interrupt, step seconds counter
ISR(TIMER1_COMPA_vect){
	system_tick();
	dhcp_tick();
	uptime_sec++;
	if (uptime_sec>59) {
		uptime_sec=0;
		uptime_min++;
	}
	if (uptime_min>59) {
		uptime_min=0;
		uptime_hour++;
	}
	if (uptime_hour>23) {
		uptime_hour=0;
		uptime_day++;
	}
	if (delay_sec) delay_sec--;
	if (dht_delay_sec) dht_delay_sec--;
	display_update_pending=1;
}

// Generate a 1s clock signal as interrupt
static void timer_init(void)
{
	/* write high byte first for 16 bit register access: */
	TCNT1H=0;  /* set counter to zero*/
	TCNT1L=0;
	// Mode 4 table 14-4 page 132. CTC mode and top in OCR1A
	// WGM13=0, WGM12=1, WGM11=0, WGM10=0
	TCCR1A=(0<<COM1B1)|(0<<COM1B0)|(0<<WGM11);
	TCCR1B=(1<<CS12)|(1<<CS10)|(1<<WGM12)|(0<<WGM13); // crystal clock/1024

	// divide crystal clock:
	// At what value to cause interrupt. Since we count from zero we have to subtract one.
	OCR1AH = ((F_CPU / 1024) >> 8) & 0x00FF;
	OCR1AL = ((F_CPU / 1024) & 0x00FF) - 1;
	// interrupt mask bit:
	TIMSK1 = (1 << OCIE1A);
}

// prints message to uart when pinged
static void ping_callback(uint8_t __attribute__((unused)) *srcip) {
	uart_puts_P("ICMP request\r\n");
}

// gets called whenever an arp is resolved
static void arpresolver_result_callback(uint8_t *ip,uint8_t reference_number,uint8_t *mac){
	mk_net_str(gStrbuf,ip,4,'.',10);
	uart_puts(gStrbuf);
	uart_puts_P(" is at ");
	mk_net_str(gStrbuf,mac,6,':',16);
	uart_puts(gStrbuf);
	uart_puts_P("\r\n");
	if (reference_number==TRANS_NUM_NTPMAC){
		// copy mac address over:
		memcpy(ntproutingmac,mac,sizeof(ntproutingmac));
		delay_sec=0;
		have_ntp_mac=1;
	}
	if (reference_number==TRANS_NUM_DNSMAC){
		// copy mac address over:
		memcpy(dnsroutingmac,mac,sizeof(dnsroutingmac));
		delay_sec=0;
		have_dns_mac=1;
	}
}

// starts arp process for dns and/or ntp mac if not yet resolved
// returns 1 if arp sent, 0 otherwise
static uint8_t arpresolver(void) {
	if (!have_dns_mac) {
		get_mac_with_arp((route_via_gw(mydns)) ? gwip : mydns, TRANS_NUM_DNSMAC, &arpresolver_result_callback);
		return 1;
	}
	if (!have_ntp_mac) {
		get_mac_with_arp((route_via_gw(ntpip)) ? gwip : ntpip, TRANS_NUM_NTPMAC, &arpresolver_result_callback);
		return 1;
	}
	return 0;
}

// NTP protocol handling
static void udp_client_check_for_ntp_answer(uint8_t *buf,uint16_t plen) {
	// check if ip packets are for us:
	if(eth_type_is_ip_and_my_ip(buf,plen)){
		if (client_ntp_process_answer(buf,&start_t,ntpclientportL)){
			display_update_pending=0;
			start_t -= NTP_OFFSET;
			set_system_time(start_t);
			set_zone((int32_t)mins_offset_to_utc * 60);
			print_time_to_uart();
			haveNTPanswer=1;
			ntp_retry_count=0;
		}
	}
}

// save min and max values and record time stamps
static void save_min_max_temp(void) {
	if (temperature>high_temp){
		high_temp=temperature;
		time(&high_temp_t);
	}
	if (temperature<low_temp){
		low_temp=temperature;
		time(&low_temp_t);
	}
	if (humidity>high_hum){
		high_hum=humidity;
		time(&high_hum_t);
	}
	if (humidity<low_hum){
		low_hum=humidity;
		time(&low_hum_t);
	}
}

// main loop
int main(void){
	uint8_t i;
	uint16_t plen=0;
	uint8_t link_status=0;
	uint8_t display_sec=0;
	uint8_t scroll_index=0;
	uint8_t show_ip=0;
	uint8_t arp_retry_count=0;
	uint8_t dns_retry_count=0;
	uint8_t *s;
	
	if (eeprom_read_byte(&nv_magic_number_config) == 0x55){
		// ok magic number matches accept values
		eeprom_read_block(&ntpip,&nv_ntpip,sizeof(ntpip));
		enable_eu_dst=eeprom_read_byte(&nv_enable_eu_dst);
		mins_offset_to_utc=eeprom_read_word(&nv_mins_offset_to_utc);
		eeprom_read_block(&ntphostname, &nv_ntphostname, sizeof(ntphostname));
		eeprom_read_block(&mymac, &nv_mymac, sizeof(mymac));
		ntp_update_period=eeprom_read_word(&nv_ntp_update_period);
	}
	if (eeprom_read_byte(&nv_magic_number_display) == 0xAA){
		display_24hclock=eeprom_read_byte(&nv_display_24hclock);
		display_temperature=eeprom_read_byte(&nv_display_temperature);
		intensity=eeprom_read_byte(&nv_intensity);
	}
	if (eeprom_read_byte(&nv_magic_number_password) == 0x33){
		eeprom_read_block(&password,&nv_password,sizeof(password));
		password[PASSWORD_SIZE]='\0'; // make sure it is terminated, should not be necessary
	}
	uart_init(UART_BAUD_SELECT(9600, F_CPU));
	hdlx2416_init();
	hdlx2416_intensity(intensity);
	hdlx2416_puts_P("NTPclock");
	enc28j60Init(mymac);
	print_rev_to_uart();
	init_mac(mymac);
	if (enable_eu_dst) {
		set_dst(eu_dst);
	}
	register_ping_rec_callback(ping_callback);
	timer_init();
	sei(); // interrupt on, clock starts ticking now
	while(1){
		plen=enc28j60PacketReceive(BUFFER_SIZE, buf);
		buf[BUFFER_SIZE]='\0'; // HTTP is an ASCII protocol. Make sure we have a string terminator.
		// DHCP handling. Get the initial IP
		if (init_state==1 && packetloop_dhcp_initial_ip_assignment(buf,plen)) {
			// we have an IP:
			init_state=2;
			dhcp_get_my_ip(myip,netmask,gwip,mydns);
			init_dnslkup(mydns);
			client_ifconfig(myip,netmask);
			show_ip=30; // show the ip for 30 seconds
			print_ip_to_uart();
		}
		// DHCP renew IP:
		plen=packetloop_dhcp_renewhandler(buf,plen);
		dat_p=packetloop_arp_icmp_tcp(buf,plen);
		if(dat_p==0){
			// no http request
			if (plen>0){
				// possibly a udp message
				udp_client_check_for_dns_answer(buf,plen);
				udp_client_check_for_ntp_answer(buf,plen);
				continue;
			}
			// we are idle here (no incoming packet to process).
			if (enc28j60linkup()!=link_status) {
				if ((link_status=enc28j60linkup())) {
					uart_puts_P("Link up\r\n");
					init_state=0;
					delay_sec=0;
				} else {
					uart_puts_P("Link down\r\n");
				}
			}
			// scroll the ip address over display
			if (show_ip && display_update_pending){
				show_ip--;
				display_update_pending=0;
				mk_net_str(gStrbuf,myip,4,'.',10);
				i=strlen(gStrbuf);
				strcat_P(gStrbuf,PSTR("        "));
				hdlx2416_putsn(gStrbuf+scroll_index,8);
				scroll_index++;
				if (scroll_index==i) scroll_index=0;
			}
			// periodically read the temperature and humidity
			if (dht_delay_sec==0) {
				dht_delay_sec=10;
				dht_gettemperaturehumidity(&temperature,&humidity);
				if (haveNTPanswer) save_min_max_temp();
			}
			if (init_state==0 && delay_sec==0){
				// request initial IP assignment
				init_state=1;
				have_ntp_mac=0;
				have_dns_mac=0;
				hdlx2416_puts_P("WaitDHCP");
				uart_puts_P("DHCP request\r\n");
				init_dhcp(mymac[5]);
			}
			if (init_state==2 && delay_sec==0){
				// resolve ARPs
				if (!have_dns_mac || !have_ntp_mac) {
					uart_puts_P("ARP request\r\n");
					if (arpresolver()) {
						delay_sec=2; // retry after 2 sec if no answer
						if (++arp_retry_count==15){
							arp_retry_count=0;
							// reinitialize clock after multiple retries
							init_state=0;
							delay_sec=0;
						}
					}
				}
				if (have_dns_mac && have_ntp_mac) {
					// all ARPs resolved
					init_state=3;
					delay_sec=0;
					dns_state=0;
				}
			}
			if (init_state==3) {
				// DNS lookup
				if (dns_state==0){
					delay_sec=5; // retry after 5 sec if no answer
					dns_state=1;
					uart_puts_P("DNS request\r\n");
					dnslkup_request(buf,ntphostname,ntproutingmac);
				}
				if (dns_state==1 && dnslkup_haveanswer()){
					// dns-lookup succeeded:
					dns_state=2;
					dnslkup_get_ip(ntpip);
					mk_net_str(gStrbuf,ntpip,4,'.',10);
					uart_puts_P("NTP IP:");
					uart_puts(gStrbuf);
					uart_puts_P("\r\n");
					init_state = 4;
				}
				if (dns_state!=2 && delay_sec==0){
					// retry if dns-lookup failed:
					dns_state=0;
					if (dnslkup_get_error_info()) {
						uart_puts_P("DNS Error\r\n");
					}
					if (++dns_retry_count==6) {
						dns_retry_count=0;
						// reinitialize clock after multiple retries
						init_state=0;
						delay_sec=0;
					}
				}
			}
			if (init_state==4){
				// ready for initial NTP
				ntpclientportL=mymac[5];
				delay_sec=0;
				haveNTPanswer=0;
				init_state=5;
			}
			if (init_state==5){
				// request NTP
				if (haveNTPanswer!=1 && delay_sec==0 && link_status){
					if (ntp_retry_count<6){
						delay_sec=5; // retry after 5 sec if no answer
						ntpclientportL++; // new src port
						uart_puts_P("NTP request\r\n");
						client_ntp_request(buf,ntpip,ntpclientportL,ntproutingmac);
						ntp_retry_count++;
					}else{
						ntp_retry_count=0;
						// reinitialize clock after multiple retries
						init_state=0;
						delay_sec=0;
					}
				}
				// update the display
				if (!show_ip && haveNTPanswer && display_update_pending){
					display_update_pending=0;
					display_sec++;
					if (display_sec>5 && display_temperature){
						print_dht_to_display();
					}else{
						print_time_to_display();
					}
					if (display_sec>9) display_sec=0;
				}
			}
		} else {
			// dat_p !=0
			// tcp port 80 begin
			// prints http request method line
			s = &buf[dat_p];
			while (*s) {
				uart_putc(*s);
				if (*s++=='\n') break;
			}
			// check method
			if (strncmp_P((char *)&(buf[dat_p]),PSTR("GET "),4)==0){
				// get method:
				analyse_get_url((char *)&(buf[dat_p+4]));
			} else if (strncmp_P((char *)&(buf[dat_p]),PSTR("POST "),5)==0){
				// post method:
				if (analyse_post_url((char *)&(buf[dat_p+5]))) {
					// reinitialize clock
					init_state=0;
					delay_sec=0;
				}
			} else {
				// other methods:
				dat_p=http501notimpl();
			}
			// a web page has been written to the tcp send buf
			uart_puts_P("Reply len=");
			itoa(dat_p,gStrbuf,10);
			uart_puts(gStrbuf);
			uart_puts_P("\r\n");
			www_server_reply(buf,dat_p); // send web page data
			// tcp port 80 end
		}
	}
	return (0);
}
