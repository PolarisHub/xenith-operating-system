#ifndef XENITH_TERMIOS_H
#define XENITH_TERMIOS_H
#include <stddef.h>
#include <stdint.h>

#define TCGETS 0x5401u
#define TCSETS 0x5402u
#define TCSETSW 0x5403u
#define TCSETSF 0x5404u
#define TIOCGWINSZ 0x5413u
#define TIOCSWINSZ 0x5414u
#define TIOCGPGRP 0x540Fu
#define TIOCSPGRP 0x5410u
#define TIOCGPTN 0x80045430u
#define FIONREAD 0x541Bu

#define ICRNL 0x0100u
#define OPOST 0x0001u
#define ONLCR 0x0004u
#define ISIG 0x0001u
#define ICANON 0x0002u
#define ECHO 0x0008u
#define ECHOE 0x0010u
#define ECHOK 0x0020u
#define ECHONL 0x0040u

#define VINTR 0
#define VQUIT 1
#define VERASE 2
#define VKILL 3
#define VEOF 4
#define VEOL 5
#define VSUSP 6
#define VMIN 7
#define VTIME 8
#define NCCS 16

struct xenith_termios {
    uint32_t input_flags;
    uint32_t output_flags;
    uint32_t control_flags;
    uint32_t local_flags;
    unsigned char control_characters[NCCS];
};

struct xenith_winsize {
    uint16_t rows;
    uint16_t columns;
    uint16_t pixel_width;
    uint16_t pixel_height;
};

#endif
