#include "bsp.h"
#include <stdlib.h>

BspVM *init_vm(void) {
	BspVM *vm = malloc(sizeof(BspVM));
	vm->patch_space.data = NULL;
	vm->patch_space.size = 0;
	vm->file_buffer.data = NULL;
	vm->file_buffer.size = 0;
	vm->stack.data = NULL;
	vm->stack.elements = 0;
	vm->message_buffer.data = NULL;
	vm->message_buffer.size = 0;
	for (size_t i = 0; i < 256; i++) {
		vm->variables[i] = 0;
	}
	vm->ip = 0;
	vm->fp.is_locked = false;
	vm->fp.position = 0;

	return vm;
}

void destroy_vm(BspVM *vm) {
	if (vm->patch_space.data != NULL) {
		free(vm->patch_space.data);
	}
	if (vm->file_buffer.data != NULL) {
		free(vm->file_buffer.data);
	}
	if (vm->stack.data != NULL) {
		free(vm->stack.data);
	}
	if (vm->message_buffer.data != NULL) {
		free(vm->message_buffer.data);
	}
	free(vm);
}
