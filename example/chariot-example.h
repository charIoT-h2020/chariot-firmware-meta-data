// file chariot-example.h
// contributed by CEA
// in the public domain? Or LGPLv3+
////////////////

/* Hardware text mode color constants. */
enum vga_color {
	VGA_COLOR_BLACK = 0,
	VGA_COLOR_BLUE = 1,
	VGA_COLOR_GREEN = 2,
	VGA_COLOR_CYAN = 3,
	VGA_COLOR_RED = 4,
	VGA_COLOR_MAGENTA = 5,
	VGA_COLOR_BROWN = 6,
	VGA_COLOR_LIGHT_GREY = 7,
	VGA_COLOR_DARK_GREY = 8,
	VGA_COLOR_LIGHT_BLUE = 9,
	VGA_COLOR_LIGHT_GREEN = 10,
	VGA_COLOR_LIGHT_CYAN = 11,
	VGA_COLOR_LIGHT_RED = 12,
	VGA_COLOR_LIGHT_MAGENTA = 13,
	VGA_COLOR_LIGHT_BROWN = 14,
	VGA_COLOR_WHITE = 15,
};
 
static inline uint8_t vga_entry_color(enum vga_color fg, enum vga_color bg) 
{
	return fg | bg << 4;
}
 
static inline uint16_t vga_entry(unsigned char uc, uint8_t color) 
{
	return (uint16_t) uc | (uint16_t) color << 8;
}

// all this below is in kernel.c
extern size_t strlen(const char*); 
extern size_t terminal_row;
extern size_t terminal_column;
extern uint8_t terminal_color;
extern uint16_t* terminal_buffer;
void terminal_setcolor(uint8_t color);
void terminal_putentryat(char c, uint8_t color, size_t x, size_t y);
void terminal_putchar(char c);
void terminal_write(const char* data, size_t size);
void terminal_writestring(const char* data);
 
// the function showing chariot data; in hello-chariot.c
extern void show_chariot_data(void);

extern const char chariotmeta_mainboot_sha256[];
extern const char chariotmeta_format_typeinfo[];
extern const char chariotmeta_mainboot_offsetnum[];
extern const char chariotmeta_mainboot_sizenum[];
extern const char chariotmeta_extraboot_sha256[];
extern const char chariotmeta_extraboot_offsetnum[];
extern const char chariotmeta_extraboot_sizenum[];
extern const char chariotmeta_extraboot_typeinfo[];
extern const char chariotmeta_codanalys_typeinfo[];
extern const char chariotmeta_version_data[];
extern const char chariotmeta_firmware_path[];
extern const char chariotmeta_firmware_license[];
extern const char chariotmeta_codanalys_data[];
