/*** file kernel.c
   taken from https://wiki.osdev.org/Bare_Bones in §Writing a kernel in C
   copyright notice unspecified.
   basile.starynkevitch@cea.fr has not written this but believe it might
   be under some open source license or in the public domain.
   Compile and use it at your own risk.
   Don't blame us for this file.
   Any even small contributions from CEA in this kernel.c file is in the public domain
   and can be compiled.
****/
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "chariot-example.h"

/* Check if the compiler thinks you are targeting the wrong operating system. */
#if defined(__linux__)
#warning "You are not using a cross-compiler, you could run into trouble"
#endif

/* This tutorial will only work for the 32-bit ix86 targets. */
#if !defined(__i386__)
#error "This tutorial needs to be compiled with a ix86-elf compiler"
#endif


size_t
strlen (const char *str)
{
  size_t len = 0;
  while (str[len])
    len++;
  return len;
}

static const size_t VGA_WIDTH = 80;
static const size_t VGA_HEIGHT = 25;

size_t terminal_row;
size_t terminal_column;
uint8_t terminal_color;
uint16_t *terminal_buffer;

void
terminal_initialize (void)
{
  terminal_row = 0;
  terminal_column = 0;
  terminal_color = vga_entry_color (VGA_COLOR_LIGHT_GREY, VGA_COLOR_BLACK);
  terminal_buffer = (uint16_t *) 0xB8000;
  for (size_t y = 0; y < VGA_HEIGHT; y++)
    {
      for (size_t x = 0; x < VGA_WIDTH; x++)
	{
	  const size_t index = y * VGA_WIDTH + x;
	  terminal_buffer[index] = vga_entry (' ', terminal_color);
	}
    }
}

void
terminal_setcolor (uint8_t color)
{
  terminal_color = color;
}

void
terminal_putentryat (char c, uint8_t color, size_t x, size_t y)
{
  const size_t index = y * VGA_WIDTH + x;
  terminal_buffer[index] = vga_entry (c, color);
}

void
terminal_putchar (char c)
{
  terminal_putentryat (c, terminal_color, terminal_column, terminal_row);
  if (++terminal_column == VGA_WIDTH)
    {
      terminal_column = 0;
      if (++terminal_row == VGA_HEIGHT)
	terminal_row = 0;
    }
}

void
terminal_write (const char *data, size_t size)
{
  for (size_t i = 0; i < size; i++)
    {
      if (data[i] == '\n')
	{
	  terminal_row++;
	  terminal_column = 0;
	}
      else
	terminal_putchar (data[i]);
    }
}

void
terminal_writestring (const char *data)
{
  terminal_write (data, strlen (data));
}

void
kernel_main (void)
{
  /* Initialize terminal interface */
  terminal_initialize ();

  terminal_writestring ("Hello, kernel World!\n");
  show_chariot_data ();
}
