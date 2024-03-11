#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bsp.h"

static inline void print_help(void);
static inline WORD patch_with_filenames(
    const char *, const char *, const char *);
static inline WORD patch_with_files(FILE *, FILE *, FILE *);
static inline void print_err(char *, ...);

int main(int argc, char **argv) {
	if (argc < 4) {
		print_help();
		return 0;
	}

	char *input_fname = argv[1];
	char *patch_fname = argv[2];
	char *output_fname = argv[3];

	WORD patch_result =
	    patch_with_filenames(input_fname, patch_fname, output_fname);
	WORD error = get_interpreter_error_code();

	if (error != BSP_ERR_NONE) {
		print_err(
		    "Fatal error encountered while patching near address 0x%02x: %s\n",
		    get_interpreter_position_at_exit(), get_interpreter_error_string());
		return 1;
	}

	if (patch_result == (WORD)0) {
		print_err("Successfully patched!\n");
	} else {
		print_err("Patch failed!\n");
	}

	return (int)patch_result;
}

WORD patch_with_filenames(
    const char *input_fn, const char *patch_fn, const char *output_fn) {

	if (strcmp(input_fn, output_fn) == 0) {
		// sanity check
		fprintf(stderr, "Output file cannot be the same as input file!");
		return 1;
	}

	FILE *input = fopen(input_fn, "rb");
	if (input == NULL) {
		perror("Can't open input file");
		return 1;
	}

	FILE *patch = fopen(patch_fn, "rb");
	if (patch == NULL) {
		perror("Can't open patch file");
		return 1;
	}

	FILE *output = fopen(output_fn, "w+b");
	if (output == NULL) {
		perror("Can't open output file");
		return 1;
	}

	return patch_with_files(input, patch, output);
}

static int print_handler(const BYTE *msg) {
	// generic print handler...
	return printf("%s\n", msg);
}

static WORD menu_handler(const BspMenu *menu) {
	int counter = 1;
	BspMenu *head = menu;
	while (head->next != NULL) {
		printf("%d. %s\n", counter++, head->menu_text);
		head = head->next;
	}

	// TODO kinda risky here
	int input = 0;
	do {
		printf("Make your selection: ");
		scanf("%d", &input);
	} while ((input < 1) || (input >= counter));
	return (WORD)input - 1;
}

WORD patch_with_files(FILE *input, FILE *patch, FILE *output) {
	// assumes files are already open
	BspVM *vm = init_vm();

	// use default print handler
	vm->handlers.print = print_handler;
	vm->handlers.menu = menu_handler;

	{ // copy the BSP to the patch_space
		fseek(patch, 0L, SEEK_END);
		WORD patch_size = (WORD)ftell(patch);

		fseek(patch, 0L, SEEK_SET);
		vm->patch_space.data = malloc(patch_size * sizeof(BYTE));
		vm->patch_space.size = patch_size;
		fread(vm->patch_space.data, sizeof(BYTE), (size_t)patch_size, patch);

		fclose(patch);
	}

	{ // copy the input file to the file_buffer
		fseek(input, 0L, SEEK_END);
		WORD buf_size = (WORD)ftell(input);

		fseek(input, 0L, SEEK_SET);
		vm->file_buffer.size = buf_size;
		vm->file_buffer.data = malloc(buf_size * sizeof(BYTE));
		fread(vm->file_buffer.data, sizeof(BYTE), (size_t)buf_size, input);

		fclose(input);
	}

	WORD result = interpret(vm);

	if (result == 0) {
		// dump the file output
		(void)fwrite(
		    vm->file_buffer.data, sizeof(BYTE), vm->file_buffer.size, output);
	}

	// done
	destroy_vm(vm);
	fclose(output);

	return (WORD)result;
}

void print_err(char *msg, ...) {
	va_list a;
	va_start(a, msg);
	vfprintf(stderr, msg, a);
	va_end(a);
}

void print_help(void) {
	printf("bsppatch input.gbc patch.bsp output.gbc\n");
}
