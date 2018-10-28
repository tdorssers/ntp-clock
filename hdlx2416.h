/*
 * hdlx2416.h
 *
 * Created: 6-10-2018 13:24:47
 *  Author: Tim Dorssers
 */ 

// PC0 -> D4
// PC1 -> D5
// PC2 -> D6
// PC3 -> CU
// PD2 -> D0
// PD3 -> D1
// PD4 -> D2
// PD5 -> D3
// PD6 -> WR display 0
// PD7 -> WR display 1
// PB0 -> A0
// PB1 -> A1

#ifndef HDLX2416_H_
#define HDLX2416_H_

#include <avr/io.h>
#include <avr/pgmspace.h>

#define hdlx2416_puts_P(__s) hdlx2416_puts_p(PSTR(__s))

extern void hdlx2416_putc(char c);
extern void hdlx2416_intensity(uint8_t i);
extern void hdlx2416_puts(const char *s);
extern void hdlx2416_putsn(const char *s, uint8_t n);
extern void hdlx2416_puts_p(const char *progmem_s);
extern void hdlx2416_goto(uint8_t pos);
extern void hdlx2416_init(void);

#endif /* HDLX2416_H_ */