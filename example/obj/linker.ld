/*** file linker.ld - a linker script
   taken from https://wiki.osdev.org/Bare_Bones in §Linking the kernel
   copyright notice unspecified. Adapted for CHARIOT meta-data.
   basile.starynkevitch@cea.fr has not written this but believe it might
   be under some open source license or in the public domain.
   Compile and use it at your own risk.
   Don't blame us for this file.

   Any even small contributions from CEA in this linker.ld file is in the public domain
   and can be compiled.

   Adapted to CHARIOT meta-data. Read more about linker scripts in
   https://sourceware.org/binutils/docs/ld/Scripts.html
****/
/* The bootloader will look at this image and start execution at the symbol
   designated as the entry point. */
ENTRY(_start)
 
/* Tell where the various sections of the object files will be put in the final
   kernel image. */
SECTIONS
{
	/* Begin putting sections at 1 MiB, a conventional place for kernels to be
	   loaded at by the bootloader. */
	. = 1M;
 
	/* First put the multiboot header, as it is required to be put very early
	   early in the image or the bootloader won't recognize the file format.
	   Next we'll put the .text section. */

	.text BLOCK(4K) : ALIGN(4K)
	{
		*(.multiboot)
		*(.text)
	}
 
	/* Read-only data. */
	.rodata BLOCK(4K) : ALIGN(4K)
	{
		*(.rodata)
	}

	/* Read-write data (initialized) */
	.data BLOCK(4K) : ALIGN(4K)
	{
		*(.data)
	}
 
	/* Read-write data (uninitialized) and stack */
	   .bss BLOCK(4K) : ALIGN(4K)
	   {
	   	*(COMMON)
	   	*(.bss)
	   }  
 
	/* The compiler may produce other sections, by default it will put them in
	   a segment with the same name. Simply add stuff here as needed. */
	   
}


/* end of file linker.ld */
