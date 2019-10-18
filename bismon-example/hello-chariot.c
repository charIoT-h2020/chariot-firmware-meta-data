// file hello-chariot.c
// in the public domain
// contributed by CEA

/// this example is not very meaningful, but it does exercise our static analyzer.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "chariot-example.h"

volatile int chariot_linecount;

void
terminal_chariot_newline (void)
{
  terminal_putchar ('\n');
  chariot_linecount++;
}

void
show_chariot_data (void)
{
  terminal_setcolor (vga_entry_color
		     (VGA_COLOR_LIGHT_BROWN, VGA_COLOR_BLACK));
  terminal_writestring ("CHARIOT\nmainboot:");
  chariot_linecount++;
  terminal_writestring (&chariotmeta_mainboot_sha256[0]);
  terminal_chariot_newline ();
  terminal_writestring ("format:");
  terminal_writestring (&chariotmeta_format_typeinfo[0]);
  terminal_chariot_newline ();
  terminal_writestring ("mainoffset:");
  terminal_writestring (&chariotmeta_mainboot_offsetnum[0]);
  terminal_chariot_newline ();
  terminal_writestring ("mainsize:");
  terminal_writestring (&chariotmeta_mainboot_sizenum[0]);
  terminal_chariot_newline ();
  terminal_writestring ("extraboot:");
  terminal_writestring (&chariotmeta_extraboot_sha256[0]);
  terminal_chariot_newline ();
  terminal_writestring ("extraoffset:");
  terminal_writestring (&chariotmeta_extraboot_offsetnum[0]);
  terminal_chariot_newline ();
  terminal_writestring ("extrasize:");
  terminal_writestring (&chariotmeta_extraboot_sizenum[0]);
  terminal_chariot_newline ();
  terminal_writestring ("extratype:");
  terminal_writestring (&chariotmeta_extraboot_typeinfo[0]);
  terminal_chariot_newline ();
  terminal_writestring ("codanalys-type:");
  terminal_writestring (&chariotmeta_codanalys_typeinfo[0]);
  terminal_chariot_newline ();
  terminal_writestring ("version:");
  terminal_writestring (&chariotmeta_version_data[0]);
  terminal_chariot_newline ();
  terminal_writestring ("firmware:");
  terminal_writestring (&chariotmeta_firmware_path[0]);
  terminal_chariot_newline ();
  terminal_writestring ("license:");
  terminal_writestring (&chariotmeta_firmware_license[0]);
  terminal_chariot_newline ();
  terminal_writestring ("codanalysdata:");
  terminal_writestring (&chariotmeta_codanalys_data[0]);
  terminal_chariot_newline ();
}

// end of file hello-chariot.c
