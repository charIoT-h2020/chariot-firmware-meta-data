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
  terminal_writestring (&chariotmeta_mainboot_sha256[0]);
  terminal_writestring ("\nformat:");
  terminal_writestring (&chariotmeta_format_typeinfo[0]);
  terminal_writestring ("\nmainoffset:");
  terminal_writestring (&chariotmeta_mainboot_offsetnum[0]);
  terminal_writestring ("\nmainsize:");
  terminal_writestring (&chariotmeta_mainboot_sizenum[0]);
  terminal_writestring ("\nextraboot:");
  terminal_writestring (&chariotmeta_extraboot_sha256[0]);
  terminal_writestring ("\nextraoffset:");
  terminal_writestring (&chariotmeta_extraboot_offsetnum[0]);
  terminal_writestring ("\nextrasize:");
  terminal_writestring (&chariotmeta_extraboot_sizenum[0]);
  terminal_writestring ("\nextratype:");
  terminal_writestring (&chariotmeta_extraboot_typeinfo[0]);
  terminal_writestring ("\ncodanalys-type:");
  terminal_writestring (&chariotmeta_codanalys_typeinfo[0]);
  terminal_writestring ("\nversion:");
  terminal_writestring (&chariotmeta_version_data[0]);
  terminal_writestring ("\nfirmware:");
  terminal_writestring (&chariotmeta_firmware_path[0]);
  terminal_writestring ("\nlicense:");
  terminal_writestring (&chariotmeta_firmware_license[0]);
  terminal_writestring ("\ncodanalysdata:");
  terminal_writestring (&chariotmeta_codanalys_data[0]);
  terminal_writestring ("\n");
}

// end of file hello-chariot.c
