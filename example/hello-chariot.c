// file hello-chariot.c
// in the public domain
// contributed by CEA


#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "chariot-example.h"

void
show_chariot_data (void)
{
  terminal_setcolor (vga_entry_color
		     (VGA_COLOR_LIGHT_BROWN, VGA_COLOR_BLACK));
  terminal_writestring ("CHARIOT\nmainboot:");
  terminal_writestring ("\nformat:");
  terminal_writestring ("\nmainoffset:");
  terminal_writestring ("\nmainsize:");
  terminal_writestring ("\nextraboot:");
  terminal_writestring ("\nextraoffset:");
  terminal_writestring ("\nextrasize:");
  terminal_writestring ("\nextratype:");
  terminal_writestring ("\ncodanalys-type:");
  terminal_writestring ("\nversion:");
  terminal_writestring ("\nfirmware:");
  terminal_writestring ("\nlicense:");
  terminal_writestring ("\ncodanalysdata:");
  terminal_writestring ("\n");
}

// end of file hello-chariot.c
