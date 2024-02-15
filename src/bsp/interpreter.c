/// @file

#include "bsp.h"
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "sha1/sha1.h"

#ifndef NDEBUG
#include <stdarg.h>
#define DEBUG_PRINT_LN(...) \
	DEBUG_PRINT(__VA_ARGS__); \
	DEBUG_PRINT("\n")
#else
#define DEBUG_PRINT(...)
#define DEBUG_PRINT_LN(...)
#endif

#define INVALID_WORD UINT32_MAX
#define INVALID_HALFWORD UINT16_MAX
#define INVALID_BYTE UINT8_MAX

static WORD interpreter_error_code = BSP_ERR_NONE;
static WORD interpreter_position_at_exit = 0;

static BYTE read_byte(BspVM *, bool);
static HALFWORD read_half_word(BspVM *, bool);
static WORD read_word(BspVM *, bool);
static BYTE read_file_byte(BspVM *, bool);
static HALFWORD read_file_half_word(BspVM *, bool);
static WORD read_file_word(BspVM *, bool);
static WORD pop_stack(BspVM *);
static void push_stack(BspVM *, WORD);
static void push_string(BspVM *, const BYTE *, WORD);
static WORD ips_patch(BspVM *, WORD);
typedef struct {
	BYTE data[4];
	BYTE size;
} Rune;
static Rune utf8_from_data(const BYTE *);
static WORD utf8_to_codepoint(const Rune);
static Rune codepoint_to_utf8(const WORD);

#ifndef NDEBUG
static inline void DEBUG_PRINT(char *msg, ...);
#endif

WORD interpret(BspVM *vm) {
	bool must_quit = false;
	WORD retval = 0;

	while (!must_quit) {
		if (interpreter_error_code != BSP_ERR_NONE) {
			/* quit immediately */
			interpreter_position_at_exit = vm->ip;
			return INVALID_WORD;
		}

// me when I reinvent exceptions
#define BREAK_ON_ERROR \
	if (interpreter_error_code != BSP_ERR_NONE) break;

#define READ_BYTE(x, y) \
	read_byte(x, y); \
	BREAK_ON_ERROR

#define READ_WORD(x, y) \
	read_word(x, y); \
	BREAK_ON_ERROR

#define READ_HALF_WORD(x, y) \
	read_half_word(x, y); \
	BREAK_ON_ERROR

#define READ_FILE_BYTE(x, y) \
	read_file_byte(x, y); \
	BREAK_ON_ERROR

#define READ_FILE_WORD(x, y) \
	read_file_word(x, y); \
	BREAK_ON_ERROR

#define READ_FILE_HALF_WORD(x, y) \
	read_file_half_word(x, y); \
	BREAK_ON_ERROR

#ifndef NDEBUG
#define __d(...) (void)DEBUG_PRINT_LN(__VA_ARGS__)
#else
#define __d(...)
#endif

#define GET_VAL_FROM_VAR(destination, varname) \
	BYTE varname = READ_BYTE(vm, true); \
	__d("(#%d => %d)", varname, vm->variables[varname]); \
	destination = vm->variables[varname];

		__d("\n--------------\norg: %8x", vm->ip);
		enum BspOpcode opcode = READ_BYTE(vm, true);

		switch (opcode) {
			case NOP: {
				__d("nop");
				break;
			}
			case RET: {
				__d("ret");
			do_return:
				if (vm->stack.elements == 0) {
					__d("0");
					retval = 0;
					must_quit = true;
					break;
				}
				__d("from subroutine");
				vm->ip = pop_stack(vm);
				break;
			}
			case RETZ: {
				__d("retz");

				BYTE which_var = READ_BYTE(vm, true);

				__d("check #%d == 0", which_var);

				if (vm->variables[which_var] == 0) {
					__d("yes");
					goto do_return;
				}

				__d("not fulfilled, moving on");
				break;
			}
			case RETNZ: {
				__d("retnz");

				BYTE which_var = READ_BYTE(vm, true);

				__d("check #%d == 0", which_var);

				if (vm->variables[which_var] != 0) {
					__d("yes");
					goto do_return;
				}

				__d("not fulfilled, moving on");
				break;
			}
			case JP_WD:
			case JP_VAR: {
				__d("jump");

				WORD jp_pos;

				if (opcode == JP_WD) {
					jp_pos = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(jp_pos, jp_pos_var);
				}

				__d("to %2x", jp_pos);

				vm->ip = jp_pos;
				break;
			}
			case JUMPZ_VAR_WD:
			case JUMPZ_VAR_VAR: {
				__d("jumpz");

				BYTE which_var = READ_BYTE(vm, true);
				WORD address;

				if (opcode == JUMPZ_VAR_WD) {
					address = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(address, address_var);
				}

				__d("check #%d == 0", which_var);

				if (vm->variables[which_var] == 0) {
					__d("do jump to %x", address);
					vm->ip = address;
					break;
				}

				__d("not fulfilled, moving on");
				break;
			}
			case JUMPNZ_VAR_WD:
			case JUMPNZ_VAR_VAR: {
				__d("jumpnz");

				BYTE which_var = READ_BYTE(vm, true);
				WORD address;

				if (opcode == JUMPNZ_VAR_WD) {
					address = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(address, address_var);
				}

				__d("check #%d != 0", which_var);

				if (vm->variables[which_var] != 0) {
					__d("do jump to %x", address);
					vm->ip = address;
					break;
				}

				__d("not fulfilled, moving on");
				break;
			}
			case CALL_WD:
			case CALL_VAR: {
				__d("call");

				WORD new_loc;

				if (opcode == CALL_WD) {
					new_loc = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(new_loc, new_loc_var);
				}

				__d("subroutine %2x", new_loc);

				push_stack(vm, vm->ip);
				vm->ip = new_loc;
				break;
			}
			case CALLZ_VAR_WD:
			case CALLZ_VAR_VAR:
			case CALLNZ_VAR_WD:
			case CALLNZ_VAR_VAR: {
				if ((opcode == CALLZ_VAR_WD)||(opcode == CALLZ_VAR_VAR)) {
					__d("callz");
				} else {
					__d("callnz");
				}

				BYTE which_var = READ_BYTE(vm, true);
				WORD callto;

				if ((opcode == CALLZ_VAR_WD)||(opcode==CALLNZ_VAR_WD)) {
					callto = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(callto, callto_var);
				}

				WORD var_value = vm->variables[which_var];

				if ((opcode==CALLZ_VAR_WD)||(opcode==CALLZ_VAR_VAR)) {
					if (var_value != 0) {
						__d("Not fulfilled, moving on");
						break;
					}
					__d("#%d == 0", which_var);
				} else {
					if (var_value == 0) {
						__d("Not fulfilled, moving on");
						break;
					}
					__d("#%d != 0", which_var);
				}

				__d("subroutine %x", callto);
				push_stack(vm, vm->ip);
				vm->ip = callto;
				break;
			}
			case EXIT_WD:
			case EXIT_VAR: {
				__d("exit");

				if (opcode == EXIT_WD) {
					retval = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(retval, retval_var);
				}

				__d("returning %2x", retval);

				must_quit = true;
				break;
			}
			case PUSH_WD:
			case PUSH_VAR: {
				__d("push");

				WORD value;

				if (opcode == PUSH_WD) {
					value = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(value, value_var);
				}

				__d("%2x", value);

				push_stack(vm, value);
				break;
			}
			case POP: {
				__d("pop");

				BYTE which_var = READ_BYTE(vm, true);
				__d("to #%d", which_var);

				vm->variables[which_var] = pop_stack(vm);
				break;
			}
			case LENGTH: {
				__d("length");

				BYTE which_var = READ_BYTE(vm, true);
				__d("to #%d", which_var);

				vm->variables[which_var] = vm->file_buffer.size;
				break;
			}
			case READBT: {
				__d("readbyte");

				BYTE value = READ_FILE_BYTE(vm, !vm->fp.is_locked);
				BYTE to_reg = READ_BYTE(vm, true);
				__d("to #%d", to_reg);

				vm->variables[to_reg] = (WORD)value;
				break;
			}
			case READHALFWD: {
				__d("readhalfword");

				HALFWORD value = READ_FILE_HALF_WORD(vm, !vm->fp.is_locked);
				BYTE to_reg = READ_BYTE(vm, true);
				__d("to #%d", to_reg);

				vm->variables[to_reg] = (WORD)value;
				break;
			}
			case READWD: {
				__d("readword");

				WORD value = READ_FILE_WORD(vm, !vm->fp.is_locked);
				BYTE to_reg = READ_BYTE(vm, true);
				__d("to #%d", to_reg);

				vm->variables[to_reg] = (WORD)value;
				break;
			}
			case GETFILEBT: {
				__d("getfilebyte");

				BYTE value = READ_FILE_BYTE(vm, false);
				BYTE to_reg = READ_BYTE(vm, true);
				__d("to #%d", to_reg);

				vm->variables[to_reg] = (WORD)value;
				break;
			}
			case GETFILEHALFWD: {
				__d("getfilehalfword");

				HALFWORD value = READ_FILE_HALF_WORD(vm, false);
				BYTE to_reg = READ_BYTE(vm, true);
				__d("to #%d", to_reg);

				vm->variables[to_reg] = (WORD)value;
				break;
			}
			case GETFILEWD: {
				__d("getfileword");

				WORD value = READ_FILE_WORD(vm, false);
				BYTE to_reg = READ_BYTE(vm, true);
				__d("to #%d", to_reg);

				vm->variables[to_reg] = (WORD)value;
				break;
			}
			case POS: {
				__d("pos");

				BYTE which_var = READ_BYTE(vm, true);
				__d("to #%d", which_var);

				vm->variables[which_var] = vm->fp.position;
				break;
			}
			case GETBT_VAR_WD:
			case GETBT_VAR_VAR: {
				__d("getbyte");

				BYTE which_var = READ_BYTE(vm, true);
				WORD what_address;

				if (opcode == GETBT_VAR_WD) {
					what_address = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(what_address, what_address_var);
				}

				__d("to #%d", which_var);
				__d("from address %2x", what_address);

				vm->variables[which_var] =
				    (WORD)vm->patch_space.data[what_address];
				break;
			}
			case BUFSTRING_WD: {
				__d("bufstring");

				WORD address = READ_WORD(vm, true);
				__d("from %2x", address);

				WORD add_str_size = 0;
				// find end of string
				{
					WORD address_find = address;
					for (;;) {
						BYTE scanned_char =
						    vm->patch_space.data[address_find++];
						if (scanned_char == '\0') {
							goto string_size_done;
						}
						add_str_size++;
					}
				}
			string_size_done:
				push_string(vm, &vm->patch_space.data[address], add_str_size);
				break;
			}
			case ADD_VAR_WD_WD:
			case ADD_VAR_WD_VAR:
			case ADD_VAR_VAR_WD:
			case ADD_VAR_VAR_VAR: {
				__d("add");

				BYTE target_var = READ_BYTE(vm, true);
				WORD word1;
				WORD word2;

				if ((opcode==ADD_VAR_WD_WD)||(opcode==ADD_VAR_WD_VAR)) {
					word1 = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(word1, word1_var);
				}

				if ((opcode==ADD_VAR_WD_WD)||(opcode==ADD_VAR_VAR_WD)) {
					word2 = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(word2, word2_var);
				}

				__d("to #%d", target_var);
				__d("%d + %d", word1, word2);

				vm->variables[target_var] = word1 + word2;
				break;
			}
			case GETBYTEINC: {
				__d("getbyteinc");

				BYTE var_to = READ_BYTE(vm, true);
				BYTE var_address = READ_BYTE(vm, true);
				__d("to #%d", var_to);
				__d("from address pointed by #%d", var_address);

				vm->variables[var_to] =
				    vm->patch_space.data[vm->variables[var_address]];
				vm->variables[var_address]++;
				break;
			}
			case GETBYTEDEC: {
				__d("getbytedec");

				BYTE var_to = READ_BYTE(vm, true);
				BYTE var_address = READ_BYTE(vm, true);
				__d("to #%d", var_to);
				__d("from address pointed by #%d", var_to);

				vm->variables[var_to] =
				    vm->patch_space.data[vm->variables[var_address]];
				vm->variables[var_address]--;
				break;
			}
			case BUFNUM_VAR: {
				__d("bufnum");

				BYTE which_var = READ_BYTE(vm, true);
				__d("from #%d", which_var);

				BYTE strbuf[11];
				int digits =
				    sprintf((char *)strbuf, "%d", vm->variables[which_var]);
				push_string(vm, strbuf, (WORD)(digits));
				break;
			}
			case BUFCHAR_WD:
			case BUFCHAR_VAR: {
				__d("bufchar");

				WORD codepoint;

				if (opcode == BUFCHAR_WD) {
					codepoint = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(codepoint, codepoint_var);
				}

				__d("codepoint %2x", codepoint);

				if (((codepoint > 0xd7ff) && (codepoint < 0xe000)) ||
				    (codepoint > 0x10fff)) {
					interpreter_error_code = BSP_ERR_OFF_RANGE;
					break;
				}
				Rune character = codepoint_to_utf8(codepoint);
				push_string(vm, character.data, (WORD)(character.size));
				break;
			}
			case INCREMENT: {
				__d("increment");

				BYTE which_var = READ_BYTE(vm, true);
				__d("variable #%d", which_var);

				vm->variables[which_var]++;
				break;
			}
			case DECREMENT: {
				__d("decrement");

				BYTE which_var = READ_BYTE(vm, true);
				__d("variable #%d", which_var);

				vm->variables[which_var]--;
				break;
			}
			case LMULAC_VAR_VAR_VAR_WD: {
				__d("longmulacum");

				BYTE low_at = READ_BYTE(vm, true);
				BYTE high_at = READ_BYTE(vm, true);
				BYTE val1_var = READ_BYTE(vm, true);
				WORD val2 = READ_WORD(vm, true);
				WORD val1 = vm->variables[val1_var];

				__d("modify LOW:#%d HIGH:#%d", low_at, high_at);
				__d("+ (#%d => %d) * %d", val1_var, val1, val2);

				uint64_t stored_num;
				if (low_at == high_at) {
					stored_num = (uint64_t)vm->variables[low_at];
				} else {
					stored_num = (uint64_t)vm->variables[low_at] |
					             ((uint64_t)vm->variables[high_at] << 32);
				}

				uint64_t result = stored_num + (uint64_t)val1 * (uint64_t)val2;

				vm->variables[low_at] = (WORD)(result & 0xffffffff);

				if (low_at != high_at) {
					vm->variables[high_at] = (WORD)(result >> 32);
				}

				break;
			}
			case SET_VAR_WD:
			case SET_VAR_VAR: {
				__d("set");

				BYTE which_var = READ_BYTE(vm, true);
				WORD value;

				if (opcode == SET_VAR_WD) {
					value = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(value, value_var);
				}

				__d("#%d = %2x", which_var, value);

				vm->variables[which_var] = value;
				break;
			}
			case REM_VAR_VAR_WD: {
				__d("remainder");

				BYTE var_to = READ_BYTE(vm, true);
				BYTE val1_var = READ_BYTE(vm, true);
				WORD val2 = READ_WORD(vm, true);
				WORD val1 = vm->variables[val1_var];

				__d("#%d = %d %% %d", var_to, val1, val2);

				if (val2 == 0) {
					interpreter_error_code = BSP_ERR_DIV_BY_ZERO;
					break;
				}
				vm->variables[var_to] = val1 % val2;
				break;
			}
			case DIV_VAR_VAR_WD: {
				__d("divide");

				BYTE var_to = READ_BYTE(vm, true);
				BYTE val1_var = READ_BYTE(vm, true);
				WORD val2 = READ_WORD(vm, true);
				WORD val1 = vm->variables[val1_var];

				__d("%d = %d / %d", var_to, val1, val2);

				if (val2 == 0) {
					interpreter_error_code = BSP_ERR_DIV_BY_ZERO;
					break;
				}
				vm->variables[var_to] = val1 / val2;
				break;
			}
			case MUL_VAR_WD_WD:
			case MUL_VAR_WD_VAR:
			case MUL_VAR_VAR_WD:
			case MUL_VAR_VAR_VAR: {
				__d("multiply");

				BYTE which_var = READ_BYTE(vm, true);
				WORD word1;
				WORD word2;

				if ((opcode==MUL_VAR_WD_WD)||(opcode==MUL_VAR_WD_VAR)){
					word1 = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(word1, word1_var);
				}

				if ((opcode==MUL_VAR_WD_WD)||(opcode==MUL_VAR_VAR_WD)) {
					word2 = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(word2, word2_var);
				}

				__d("#%d = %d * %d", which_var, word1, word2);

				vm->variables[which_var] = word1 * word2;
				break;
			}
			case PRINTBUF: {
				__d("printbuf");

				/* ensure message is terminated properly before sending
				 * it to the handler
				 */
				vm->message_buffer.data[vm->message_buffer.size] = '\0';

				vm->handlers.print(vm->message_buffer.data);

				/* reset the buffer */
				free(vm->message_buffer.data);
				vm->message_buffer.data = NULL;
				vm->message_buffer.size = 0;
				break;
			}
			case PRINT_WD:
			case PRINT_VAR: {
				__d("print");

				WORD string_addr;

				if (opcode == PRINT_WD) {
					string_addr = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(string_addr, string_addr_var);
				}

				vm->handlers.print(&vm->patch_space.data[string_addr]);
				break;
			}
			case IFLT_VAR_WD_WD:
			case IFLT_VAR_VAR_WD:
			case IFLT_VAR_WD_VAR:
			case IFLT_VAR_VAR_VAR: {
				__d("iflt");

				BYTE which_var = READ_BYTE(vm, true);
				WORD value;
				WORD address;

				if ((opcode == IFLT_VAR_WD_WD) || (opcode == IFLT_VAR_WD_VAR)) {
					value = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(value, value_var);
				}

				if ((opcode == IFLT_VAR_WD_WD) || (opcode == IFLT_VAR_VAR_WD)) {
					address = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(address, address_var);
				}

				__d("check #%d < %d", which_var, value);

				if (vm->variables[which_var] < value) {
					__d("yes, jump to %x", address);
					vm->ip = address;
					break;
				}

				__d("no, moving on");
				break;
			}
			case IFGT_VAR_WD_WD:
			case IFGT_VAR_VAR_WD:
			case IFGT_VAR_WD_VAR:
			case IFGT_VAR_VAR_VAR: {
				__d("ifgt");

				BYTE which_var = READ_BYTE(vm, true);
				WORD value;
				WORD address;

				if ((opcode == IFGT_VAR_WD_WD) || (opcode == IFGT_VAR_WD_VAR)) {
					value = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(value, value_var);
				}

				if ((opcode == IFGT_VAR_WD_WD) || (opcode == IFGT_VAR_VAR_WD)) {
					address = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(address, address_var);
				}

				__d("check #%d > %d", which_var, value);

				if (vm->variables[which_var] > value) {
					__d("yes, jump to %x", address);
					vm->ip = address;
					break;
				}

				__d("no, moving on");
				break;
			}
			case IFGE_VAR_WD_WD:
			case IFGE_VAR_VAR_WD:
			case IFGE_VAR_WD_VAR:
			case IFGE_VAR_VAR_VAR: {
				__d("ifge");

				BYTE which_var = READ_BYTE(vm, true);
				WORD value;
				WORD address;

				if ((opcode == IFGE_VAR_WD_WD) || (opcode == IFGE_VAR_WD_VAR)) {
					value = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(value, value_var);
				}

				if ((opcode == IFGE_VAR_WD_WD) || (opcode == IFGE_VAR_VAR_WD)) {
					address = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(address, address_var);
				}

				__d("check #%d >= %d", which_var, value);

				if (vm->variables[which_var] >= value) {
					__d("yes, jump to %x", address);
					vm->ip = address;
					break;
				}

				__d("no, moving on");
				break;
			}
			case IFEQ_VAR_WD_WD:
			case IFEQ_VAR_VAR_WD:
			case IFEQ_VAR_WD_VAR:
			case IFEQ_VAR_VAR_VAR: {
				__d("ifeq");

				BYTE which_var = READ_BYTE(vm, true);
				WORD value;
				WORD address;

				if ((opcode == IFEQ_VAR_WD_WD) || (opcode == IFEQ_VAR_WD_VAR)) {
					value = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(value, value_var);
				}

				if ((opcode == IFEQ_VAR_WD_WD) || (opcode == IFEQ_VAR_VAR_WD)) {
					address = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(address, address_var);
				}

				__d("check #%d == %d", which_var, value);

				if (vm->variables[which_var] == value) {
					__d("yes, jump to %x", address);
					vm->ip = address;
					break;
				}

				__d("no, moving on");
				break;
			}
			case IFNE_VAR_WD_WD:
			case IFNE_VAR_VAR_WD:
			case IFNE_VAR_WD_VAR:
			case IFNE_VAR_VAR_VAR: {
				__d("ifne");

				BYTE which_var = READ_BYTE(vm, true);
				WORD value;
				WORD address;

				if ((opcode == IFNE_VAR_WD_WD) || (opcode == IFNE_VAR_WD_VAR)) {
					value = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(value, value_var);
				}

				if ((opcode == IFNE_VAR_WD_WD) || (opcode == IFNE_VAR_VAR_WD)) {
					address = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(address, address_var);
				}

				__d("check #%d != %d", which_var, value);

				if (vm->variables[which_var] != value) {
					__d("yes, jump to %x", address);
					vm->ip = address;
					break;
				}

				__d("no, moving on");
				break;
			}
			case SUB_VAR_WD_WD:
			case SUB_VAR_WD_VAR:
			case SUB_VAR_VAR_WD:
			case SUB_VAR_VAR_VAR: {
				__d("subtract");

				BYTE which_var = READ_BYTE(vm, true);
				WORD val1;
				WORD val2;

				if ((opcode == SUB_VAR_WD_WD) || (opcode == SUB_VAR_WD_VAR)) {
					val1 = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(val1, val1_var);
				}

				if ((opcode == SUB_VAR_WD_WD) || (opcode == SUB_VAR_VAR_WD)) {
					val2 = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(val2, val2_var);
				}

				__d("%d = %d - %d", which_var, val1, val2);

				vm->variables[which_var] = val1 - val2;
				break;
			}
			case CHECKSHA1_VAR_WD:
			case CHECKSHA1_VAR_VAR: {
				__d("checksha1");

				BYTE ret_var = READ_BYTE(vm, true);
				WORD hash_addr;

				if (opcode == CHECKSHA1_VAR_WD) {
					hash_addr = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(hash_addr, hash_addr_var);
				}

				BYTE digest[20] = {0};
				(void)sha1digest(
				    digest, NULL, vm->file_buffer.data, vm->file_buffer.size);

				WORD result = 0;
				WORD addr_ptr = hash_addr;
				for (size_t i = 0; i < 20; i++) {
					if (digest[i] != vm->patch_space.data[addr_ptr++]) {
						result |= (WORD) 1 << i;
					}
				}

				vm->variables[ret_var] = result;
				break;
			}
			case SEEK_WD:
			case SEEK_VAR: {
				__d("seek");

				WORD seek_pos;

				if (opcode == SEEK_WD) {
					seek_pos = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(seek_pos, seek_pos_var);
				}

				if (!vm->fp.is_locked) {
					vm->fp.position = seek_pos;
				}
				break;
			}
			case SETSTACKSIZE_WD:
			case SETSTACKSIZE_VAR: {
				__d("setstacksize");

				WORD new_size;

				if (opcode == SETSTACKSIZE_WD) {
					new_size = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(new_size, new_size_var);
				}

				if (new_size > vm->stack.elements) {
					while (vm->stack.elements < new_size) {
						push_stack(vm, 0);
					}
				} else if (new_size < vm->stack.elements) {
					while (vm->stack.elements > new_size) {
						(void)pop_stack(vm);
					}
				}
				break;
			}
			case TRUNC_WD:
			case TRUNC_VAR:
			case TRUNCPOS: {
				if (opcode != TRUNCPOS) {
					__d("truncate");
				} else {
					__d("truncatepos");
				}

				WORD new_length;

				if (opcode != TRUNCPOS) {
					if (opcode == TRUNC_WD) {
						new_length = READ_WORD(vm, true);
					} else {
						GET_VAL_FROM_VAR(new_length, new_length_var);
					}
				} else {
					new_length = vm->fp.position;
				}

				__d("change size of file buffer: %d -> %d", vm->file_buffer.size, new_length);

				if (new_length < vm->file_buffer.size) {
					memset(&vm->file_buffer.data[new_length], 0,
					    vm->file_buffer.size - new_length);
				} else if (new_length > vm->file_buffer.size) {
					BYTE *new_data = realloc(vm->file_buffer.data, new_length);
					if (new_data == NULL) {
						interpreter_error_code = BSP_ERR_NOMEM;
						break;
					}
					vm->file_buffer.data = new_data;
					memset(&vm->file_buffer.data[vm->file_buffer.size], 0,
					    new_length - vm->file_buffer.size);
				}

				vm->file_buffer.size = new_length;
				break;
			}
			case IPSPATCH_VAR_WD:
			case IPSPATCH_VAR_VAR: {
				__d("ipspatch");

				BYTE out_var = READ_BYTE(vm, true);
				WORD where;

				if (opcode == IPSPATCH_VAR_WD) {
					where = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(where, where_var);
				}

				WORD end_addr = ips_patch(vm, where);

				if (interpreter_error_code != BSP_ERR_NONE) break;

				vm->variables[out_var] = end_addr;
				break;
			}
			case MENU_VAR_WD:
			case MENU_VAR_VAR: {
				__d("menu");

				BYTE to_var = READ_BYTE(vm, true);
				WORD menu_options;

				if (opcode == MENU_VAR_WD) {
					menu_options = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(menu_options, menu_options_var);
				}

				WORD *menu_string_ptr_list =
				    (WORD *)&vm->patch_space.data[menu_options];
				WORD user_option;

				BspMenu *menu = malloc(sizeof(BspMenu));
				menu->menu_text = NULL;
				menu->next = NULL;

				BspMenu *menu_head = menu;

				size_t i = 0;
				for (;;) {
					WORD new_ptr = menu_string_ptr_list[i];
					WORD next_ptr = menu_string_ptr_list[i + 1];
					if (next_ptr != 0xffffffff) {
						menu_head->menu_text =
						    (BYTE *)&vm->patch_space.data[new_ptr];
						menu_head->next = malloc(sizeof(BspMenu));

						menu_head->next->menu_text = NULL;
						menu_head->next->next = NULL;
						menu_head = menu_head->next;
					} else {
						goto init_menu_done;
					}
					i++;
				}
			init_menu_done:
				user_option = vm->handlers.menu(menu);

				// free menu
				menu_head = menu;
				BspMenu *old_menu_head;
				for (;;) {
					old_menu_head = menu_head;
					if (menu_head->next == NULL) {
						free(old_menu_head);
						goto free_menu_done;
					}
					menu_head = menu_head->next;
					free(old_menu_head);
				}
			free_menu_done:
				vm->variables[to_var] = user_option;
				break;
			}
			case JUMPTABLE: {
				__d("jumptable");

				WORD which_jptbl_entry;
				GET_VAL_FROM_VAR(which_jptbl_entry, which_var);

				// TODO: bounds checking
				WORD indir_location = (which_jptbl_entry * (WORD) 4) + vm->ip;
				__d("-> to %x", indir_location);

				vm->ip = indir_location;
				break;
			}
			case GETHALFWDINC: {
				__d("gethalfwordinc");

				BYTE which_var = READ_BYTE(vm, true);
				BYTE address_var = READ_BYTE(vm, true);

				WORD what_address = vm->variables[address_var];

				__d("to #%d", which_var);
				__d("from address %2x", what_address);

				vm->variables[which_var] =
				    (WORD)vm->patch_space.data[what_address++];
				vm->variables[which_var] |=
				    ((WORD)vm->patch_space.data[what_address] << 8);

				vm->variables[address_var] += 2;
				break;
			}
			case GETHALFWDDEC: {
				__d("gethalfworddec");

				BYTE which_var = READ_BYTE(vm, true);
				BYTE address_var = READ_BYTE(vm, true);

				WORD what_address = vm->variables[address_var];

				__d("to #%d", which_var);
				__d("from address %2x", what_address);

				vm->variables[which_var] =
				    (WORD)vm->patch_space.data[what_address++];
				vm->variables[which_var] |=
				    ((WORD)vm->patch_space.data[what_address] << 8);

				vm->variables[address_var] -= 2;
				break;
			}
			case XORDATA_WD_WD:
			case XORDATA_WD_VAR:
			case XORDATA_VAR_WD:
			case XORDATA_VAR_VAR: {
				__d("xordata");

				WORD ps_address;
				WORD length;

				if ((opcode==XORDATA_WD_WD)||(opcode==XORDATA_WD_VAR)) {
					ps_address = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(ps_address, ps_address_var);
				}

				if ((opcode==XORDATA_WD_WD)||(opcode==XORDATA_VAR_WD)) {
					length = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(length, length_var);
				}

				WORD pos = vm->fp.position;
				for (size_t i = length; i > 0; i--) {
					vm->file_buffer.data[pos++] ^= vm->patch_space.data[ps_address++];

					if (!vm->fp.is_locked) {
						vm->fp.position = pos;
					}
				}
				break;
			}
			case FILLBT_WD_BT:
			case FILLBT_WD_VAR:
			case FILLBT_VAR_BT:
			case FILLBT_VAR_VAR: {
				__d("fillbyte");

				WORD count;
				BYTE value;

				if ((opcode==FILLBT_WD_BT)||(opcode==FILLBT_WD_VAR)) {
					count = READ_WORD(vm, true);
				} else {
					GET_VAL_FROM_VAR(count, count_var);
				}

				if ((opcode==FILLBT_WD_BT)||(opcode==FILLBT_VAR_BT)) {
					value = READ_BYTE(vm, true);
				} else {
					BYTE value_var = READ_BYTE(vm, true);
					value = (BYTE)(vm->variables[value_var] & 0xff);
				}

				WORD loc = vm->fp.position;
				while (count > 0) {
					vm->file_buffer.data[loc++] = value;
					if (!vm->fp.is_locked) {
						vm->fp.position = loc;
					}
					count--;
				}
				break;
			}
			default: {
				__d("Unimplemented opcode: %02x", opcode);
				interpreter_error_code = BSP_ERR_UNIMPLEMENTED;
				break;
			}
		}
	}

	interpreter_position_at_exit = vm->ip;
	return retval;

#undef READ_BYTE
#undef READ_WORD
#undef READ_HALF_WORD
#undef READ_FILE_BYTE
#undef READ_FILE_WORD
#undef READ_FILE_HALF_WORD
#undef BREAK_ON_ERROR
#undef __d
}

/**
 * @brief Reads the byte pointed to by the VM's instruction pointer
 *        from patch space.
 *        If `advance` is enabled, the instruction pointer will advance
 *        by 1 byte.
 * @param vm The BSP VM instance.
 * @param advance Whether or not to advance the instruction pointer.
 * @throw BSP_ERR_PATCH_EOF when trying to read beyond the patch space.
 */
BYTE read_byte(BspVM *vm, bool advance) {
	if (vm->ip + 1 > vm->patch_space.size) {
		interpreter_error_code = BSP_ERR_PATCH_EOF;
		return INVALID_BYTE;
	}
	BYTE val = vm->patch_space.data[vm->ip];
	if (advance) vm->ip++;
	return val;
}

/**
 * @brief Reads the half-word pointed to by the VM's instruction pointer
 *        from patch space.
 *        If `advance` is enabled, the instruction pointer will advance
 *        by 2 bytes.
 * @param vm The BSP VM instance.
 * @param advance Whether or not to advance the instruction pointer.
 * @throw BSP_ERR_PATCH_EOF when trying to read beyond the patch space.
 */
HALFWORD read_half_word(BspVM *vm, bool advance) {
	if (vm->ip + 1 > vm->patch_space.size) {
		interpreter_error_code = BSP_ERR_PATCH_EOF;
		return INVALID_HALFWORD;
	}
	HALFWORD val = vm->patch_space.data[vm->ip];
	val += (vm->patch_space.data[vm->ip + 1]) << 8;
	if (advance) vm->ip += 2;
	return val;
}

/**
 * @brief Reads the word pointed to by the VM's instruction pointer
 *        from patch space.
 *        If `advance` is enabled, the instruction pointer will advance
 *        by 4 bytes.
 * @param vm The BSP VM instance.
 * @param advance Whether or not to advance the instruction pointer.
 * @throw BSP_ERR_PATCH_EOF when trying to read beyond the patch space.
 */
WORD read_word(BspVM *vm, bool advance) {
	if (vm->ip + 1 > vm->patch_space.size) {
		interpreter_error_code = BSP_ERR_PATCH_EOF;
		return INVALID_WORD;
	}
	WORD val = vm->patch_space.data[vm->ip];
	val |= (WORD)(vm->patch_space.data[vm->ip + 1]) << 8;
	val |= (WORD)(vm->patch_space.data[vm->ip + 2]) << 16;
	val |= (WORD)(vm->patch_space.data[vm->ip + 3]) << 24;
	if (advance) vm->ip += 4;
	return val;
}

/**
 * @brief Reads the byte pointed to by the VM's file pointer
 *        from the file buffer.
 *        If `advance` is enabled, the file pointer will advance
 *        by 1 byte.
 * @param vm The BSP VM instance.
 * @param advance Whether or not to advance the file pointer.
 * @throw BSP_ERR_FILE_EOF when trying to read beyond the file buffer.
 */
BYTE read_file_byte(BspVM *vm, bool advance) {
	if (vm->fp.position + 1 > vm->file_buffer.size) {
		interpreter_error_code = BSP_ERR_FILE_EOF;
		return INVALID_BYTE;
	}
	BYTE val = vm->file_buffer.data[vm->fp.position];
	if (advance) vm->fp.position++;
	return val;
}

/**
 * @brief Reads the half-word pointed to by the VM's file pointer
 *        from the file buffer.
 *        If `advance` is enabled, the file pointer will advance
 *        by 2 bytes.
 * @param vm The BSP VM instance.
 * @param advance Whether or not to advance the file pointer.
 * @throw BSP_ERR_FILE_EOF when trying to read beyond the file buffer.
 */
HALFWORD read_file_half_word(BspVM *vm, bool advance) {
	if (vm->fp.position + 1 > vm->file_buffer.size) {
		interpreter_error_code = BSP_ERR_FILE_EOF;
		return INVALID_HALFWORD;
	}
	HALFWORD val = vm->file_buffer.data[vm->fp.position];
	val += (vm->file_buffer.data[vm->fp.position + 1] << 8);
	if (advance) vm->fp.position += 2;
	return val;
}

/**
 * @brief Reads the word pointed to by the VM's file pointer
 *        from the file buffer.
 *        If `advance` is enabled, the file pointer will advance
 *        by 4 bytes.
 * @param vm The BSP VM instance.
 * @param advance Whether or not to advance the file pointer.
 * @throw BSP_ERR_FILE_EOF when trying to read beyond the file buffer.
 */
WORD read_file_word(BspVM *vm, bool advance) {
	if (vm->fp.position + 1 > vm->file_buffer.size) {
		interpreter_error_code = BSP_ERR_FILE_EOF;
		return INVALID_WORD;
	}
	WORD val = vm->file_buffer.data[vm->fp.position];
	val |= (WORD)(vm->file_buffer.data[vm->fp.position + 1]) << 8;
	val |= (WORD)(vm->file_buffer.data[vm->fp.position + 2]) << 16;
	val |= (WORD)(vm->file_buffer.data[vm->fp.position + 3]) << 24;
	if (advance) vm->fp.position += 4;
	return val;
}

/**
 * @brief Push a word into the stack.
 *        This will `realloc` the stack's array.
 * @param vm The BSP VM instance
 * @param value The word to be pushed.
 * @throw BSP_ERR_NOMEM if the stack cannot be `realloc`'d.
 */
void push_stack(BspVM *vm, WORD value) {
	vm->stack.elements++;
	WORD *stack_realloc =
	    realloc(vm->stack.data, sizeof(WORD) * vm->stack.elements);
	if (stack_realloc == NULL) {
		free(vm->stack.data);
		interpreter_error_code = BSP_ERR_NOMEM;
		return;
	}
	vm->stack.data = stack_realloc;
	vm->stack.data[vm->stack.elements - 1] = value;
}
/**
 * @brief Push a word into the stack.
 *        This will `realloc` the stack's array.
 * @param vm The BSP VM instance
 * @param value The word to be pushed.
 * @throw BSP_ERR_NOTHING_TO_POP if the stack is empty.
 */
WORD pop_stack(BspVM *vm) {
	if (vm->stack.elements == 0) {
		interpreter_error_code = BSP_ERR_NOTHING_TO_POP;
		return INVALID_WORD;
	}
	return vm->stack.data[--vm->stack.elements];
}

/**
 * @brief Push a string into the message buffer.
 *        This will `realloc` the message buffer.
 * @param vm The BSP VM instance.
 * @param message The string to add to the buffer.
 * @param size The size of the string.
 */
void push_string(BspVM *vm, const BYTE *message, WORD size) {
	WORD old_size = vm->message_buffer.size;
	WORD new_size = old_size + size;
	// make room for nullbyte
	BYTE *new_ptr = realloc(vm->message_buffer.data, new_size + 1);
	// discard the new additions if we can't allocate more space for it
	if (new_ptr == NULL) return;
	vm->message_buffer.size = new_size;
	vm->message_buffer.data = new_ptr;
	memcpy(&vm->message_buffer.data[old_size], message, size);
}

WORD get_interpreter_error_code(void) {
	return interpreter_error_code;
}

WORD get_interpreter_position_at_exit(void) {
	return interpreter_position_at_exit;
}

const char *get_interpreter_error_string(void) {
	/* Must match BspErrors */
	const char *messages[] = {
	    "",
	    "There's nothing to pop from the stack",
	    "Division by zero",
	    "Value out of range",
	    "Invalid access",
	    "Calculation overflowed",
	    "Invalid IPS header",
	    "UTF-8 decoding error",
	    "Invalid instruction or opcode not implemented",
	    "Unexpected end of patch space",
	    "Unexpected end of file buffer",
	};
	return messages[interpreter_error_code];
}

Rune utf8_from_data(const BYTE *data) {
	Rune val;
	if (data[0] < 128) {
		// 0xxx
		val.size = 1;
	} else if (data[0] < 224) {
		// 110xxx+
		val.size = 2;
	} else if (data[0] < 240) {
		// 1110xxx+
		val.size = 3;
	} else {
		// 11110xxx+
		val.size = 4;
	}
	val.data[0] = data[0];
	if (val.size == 1) return val;
	val.data[1] = data[1];
	if (val.size == 2) return val;
	val.data[2] = data[2];
	if (val.size == 3) return val;
	val.data[3] = data[3];
	return val;
}

WORD utf8_to_codepoint(const Rune utf8) {
	WORD cpval;
	switch (utf8.size) {
		case 1:
			return (WORD)utf8.data[0];
		case 2:
			cpval = (WORD)utf8.data[1] & 63;
			cpval |= ((WORD)(utf8.data[0] & 31)) << 6;
			return cpval;
		case 3:
			cpval = (WORD)utf8.data[2] & 63;
			cpval |= ((WORD)(utf8.data[1] & 63)) << 6;
			cpval |= ((WORD)(utf8.data[0] & 15)) << 12;
			return cpval;
		case 4:
			cpval = (WORD)utf8.data[3] & 63;
			cpval |= ((WORD)(utf8.data[2] & 63)) << 6;
			cpval |= ((WORD)(utf8.data[1] & 63)) << 12;
			cpval |= ((WORD)(utf8.data[0] & 7)) << 18;
			return cpval;
			break;
	}
	return INVALID_WORD; // Not defined
}

Rune codepoint_to_utf8(const WORD codepoint) {
	Rune val = {.size = 1};
	if (codepoint < 0x80) {
		val.data[0] = (BYTE)(codepoint & 0xff);
		return val;
	};
	if (codepoint < 0x800) {
		val.size = 2;
		val.data[0] = (192 | (BYTE)(codepoint >> 6));
		val.data[1] = (128 | (BYTE)(codepoint & 63));
		return val;
	}
	if (codepoint < 0x10000) {
		val.size = 3;
		val.data[0] = (224 | (BYTE)(codepoint >> 12));
		val.data[1] = (128 | (BYTE)((codepoint >> 6) & 63));
		val.data[2] = (128 | (BYTE)(codepoint & 63));
		return val;
	}
	if (codepoint < 0x110000) {
		val.size = 4;
		val.data[0] = (112 | (BYTE)(codepoint >> 18));
		val.data[1] = (128 | (BYTE)((codepoint >> 12) & 63));
		val.data[2] = (128 | (BYTE)((codepoint >> 6) & 63));
		val.data[3] = (128 | (BYTE)(codepoint & 63));
		return val;
	}
	return val; // Not defined
}

/**
 * @brief Applies an IPS patch in patch space on the
 *        file buffer. Resizes file buffer when necessary.
 * @param vm The BSP VM instance.
 * @param address Location of the patch in BSP patch space.
 * @return WORD The ending offset into the IPS patch.
 * @throw BSP_ERR_INVALID_HEADER if the IPS magic number doesn't match.
 * @throw BSP_ERR_NOMEM if no more memory can be allocated for the resized file
 * buffer.
 */
WORD ips_patch(BspVM *vm, WORD address) {
	/* this could have been a bog-standard IPS
	 * patcher function, but too bad it's tied
	 * to BSP by adding offsets to the file pointer...
	 */
	WORD position = 0;
	BYTE *patch_file = &vm->patch_space.data[address];

	// check for magic
	if (patch_file[position++] != 'P') goto invalid_magic;
	if (patch_file[position++] != 'A') goto invalid_magic;
	if (patch_file[position++] != 'T') goto invalid_magic;
	if (patch_file[position++] != 'C') goto invalid_magic;
	if (patch_file[position++] != 'H') goto invalid_magic;

	WORD patch_address;
	HALFWORD patch_part_size;

	HALFWORD rle_count;
	BYTE rle_byte;

	for (;;) {
		patch_address = (WORD)(patch_file[position++] << 16);
		patch_address |= (WORD)(patch_file[position++] << 8);
		patch_address |= (WORD)(patch_file[position++]);
		if (patch_address == 0x454f46) { // EOF
			return position;
		}

		patch_part_size = (HALFWORD)(patch_file[position++] << 8);
		patch_part_size |= (HALFWORD)(patch_file[position++]);

		patch_address += vm->fp.position;

		WORD patch_part_end;

		if (patch_part_size == 0) {
			// this is an RLE patch part
			rle_count = (HALFWORD)(patch_file[position++] << 8);
			rle_count |= (HALFWORD)(patch_file[position++]);
			rle_byte = (BYTE)(patch_file[position++]);
			patch_part_end = patch_address + rle_count;
		} else {
			patch_part_end = patch_address + patch_part_size;
		}

		if (patch_part_end > vm->file_buffer.size) {
			WORD new_size =
			    vm->file_buffer.size + (patch_part_end - vm->file_buffer.size);
			BYTE *new_buf = realloc(vm->file_buffer.data, new_size);
			if (new_buf == NULL) {
				interpreter_error_code = BSP_ERR_NOMEM;
				return INVALID_WORD;
			}
			vm->file_buffer.data = new_buf;
			memset(&vm->file_buffer.data[vm->file_buffer.size], 0,
			    patch_part_end - vm->file_buffer.size);
			vm->file_buffer.size = new_size;
		}

		if (patch_part_size == 0) {
			// RLE
			memset(&vm->file_buffer.data[patch_address], rle_byte, rle_count);
		} else {
			memcpy(&vm->file_buffer.data[patch_address], &patch_file[position],
			    patch_part_size);
			position += patch_part_size;
		}
	}
	return INVALID_WORD;

invalid_magic:
	interpreter_error_code = BSP_ERR_INVALID_HEADER;
	return INVALID_WORD;
}

#ifndef NDEBUG
inline void DEBUG_PRINT(char *msg, ...) {
	va_list a;
	va_start(a, msg);
	(void)vfprintf(stderr, msg, a);
	va_end(a);
}
#endif
