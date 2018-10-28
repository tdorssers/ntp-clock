/*
 * hdlx2416.c
 *
 * Created: 6-10-2018 13:24:27
 *  Author: Tim Dorssers
 */ 

#include "hdlx2416.h"

static uint8_t hdlx2416_pos;

void hdlx2416_data(uint8_t d) {
	PORTC &= ~((1<<PINC0)|(1<<PINC1)|(1<<PINC2));
	PORTC |= (d >> 4) & 0x7;
	PORTD &= ~((1<<PIND2)|(1<<PIND3)|(1<<PIND4)|(1<<PIND5));
	PORTD |= (d & 0xF) << 2;
}

void hdlx2416_putc(char c) {
	uint8_t disp = (hdlx2416_pos < 4) ? PIND6 : PIND7;
	
	PORTC |= 1<<PINC3; // cu high
	PORTB &= ~((1<<PINB0)|(1<<PINB1));
	PORTB |= hdlx2416_pos & 0x3;  // addr select
	hdlx2416_pos--;
	hdlx2416_pos &= 0x7;
	PORTD &= ~(1<<disp); // wr low
	hdlx2416_data(c);
	PORTD |= 1<<disp;  // wr high
}

void hdlx2416_intensity(uint8_t i) {
	PORTC &= ~(1<<PINC3); // cu low
	PORTD &= ~((1<<PIND6)|(1<<PIND7)); // wr low
	hdlx2416_data(i << 3);
	PORTD |= (1<<PIND6)|(1<<PIND7); // wr high
}

void hdlx2416_puts(const char *s) {
	while (*s) {
		hdlx2416_putc(*s++);
	}
}

void hdlx2416_putsn(const char *s, uint8_t n) {
	uint8_t i = 0;
	
	while (s[i] && i < n) {
		hdlx2416_putc(s[i++]);
	}
}

void hdlx2416_puts_p(const char *progmem_s) {
	uint8_t c;
	
	while ((c = pgm_read_byte(progmem_s++))) {
		hdlx2416_putc(c);
	}
}

void hdlx2416_goto(uint8_t pos) {
	hdlx2416_pos = 7 - pos;
}

void hdlx2416_init(void) {
	DDRB |= (1<<PINB0)|(1<<PINB1);
	DDRC |= (1<<PINC0)|(1<<PINC1)|(1<<PINC2)|(1<<PINC3);
	DDRD |= (1<<PIND2)|(1<<PIND3)|(1<<PIND4)|(1<<PIND5)|(1<<PIND6)|(1<<PIND7);
	PORTD |= (1<<PIND6)|(1<<PIND7); // wr high
	hdlx2416_pos = 7;
}
