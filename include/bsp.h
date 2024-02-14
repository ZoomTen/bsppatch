/**
 * @file
 */
#ifndef BSP_H
#define BSP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef uint8_t BYTE;
typedef uint16_t HALFWORD;
typedef uint32_t WORD;

/**
 * @brief Generic print handler.
 */
typedef int(BspPrintHandler)(const BYTE *);

typedef struct {
	WORD position;
	bool is_locked;
} BspFilePointer;

/**
 * @brief A way to keep track of sizes of data.
 */
typedef struct {
	BYTE *data;
	WORD size;
} BspContainer;

typedef BspContainer BspPatchSpace;
typedef BspContainer BspFileBuffer;
typedef BspContainer BspMessageBuffer;

/**
 * @brief This is similar to a BspContainer, except
 *        the elements have a much larger range.
 */
typedef struct {
	WORD *data;
	size_t elements;
} BspStack;

typedef struct {
	BspPrintHandler *print;
} BspHandlers;

/**
 * @brief This holds the state of the BSP engine as the script is run.
 *
 * I'm calling this a "VM", but I don't think the phrase "virtual machine"
 * or "interpreter" (as in machine) actually appears anywhere in the documentation,
 * but I feel like that's basically what it is and it makes it sound fancier.
 */
typedef struct {
	BspPatchSpace patch_space;
	BspFileBuffer file_buffer;
	WORD variables[256];
	/**
	 * @brief The VM's instruction pointer.
	 */
	WORD ip;
	/**
	 * @brief The VM's file buffer pointer.
	 */
	BspFilePointer fp;
	BspStack stack;
	BspMessageBuffer message_buffer;
	BspHandlers handlers;
} BspVM;

/**
 * @brief Initialize a BSP VM instance.
 * @note The patch space, stack, message buffer and file buffer
 *       are left uninitialized, so you must allocate them yourself.
 * @note You will also need to set handlers for printing the string
 *       when the VM encounters an opcode for printing.
 * @return BspVM*
 */
BspVM *init_vm(void);

/**
 * @brief Free a BSP VM instance.
 */
void destroy_vm(BspVM *);

/**
 * @brief Execute the program in the BSP VM's patch space.
 *
 * The "program" starts execution at the offset into the patch space
 * pointed to by `vm->ip`. Its return value depends on the exit value
 * of the program.

 * Upon a fatal error, the error code will be non-zero
 * and its result always -1 (0xffffffff).
 *
 * The error code can be retrieved by calling get_interpreter_error_code(),
 * and its friendly message by calling get_interpreter_error_string().
 *
 * The interpreter can also report where it was when it quit by
 * calling get_interpreter_position_at_exit().
 *
 * @param BspVM The BSP VM instance to use.
 * @return WORD The return value of the program, or -1 upon a fatal error.
 */
WORD interpret(BspVM *);

/**
 * @return WORD A value in ::BspErrors.
 */
WORD get_interpreter_error_code(void);

/**
 * @return WORD The interpreter's position in patch space.
 */
WORD get_interpreter_position_at_exit(void);

/**
 * @return char* A message explaining why the interpreter gave up.
 */
const char *get_interpreter_error_string(void);

/**
 * @brief Error values that may be returned by the interpreter.
 *        They are the return values of get_interpreter_error_code().
 */
enum BspErrors {
	BSP_ERR_NONE = 0,
	BSP_ERR_NOTHING_TO_POP,
	BSP_ERR_DIV_BY_ZERO,
	BSP_ERR_OFF_RANGE,
	BSP_ERR_INVALID_ACCESS,
	BSP_ERR_OVERFLOWED,
	BSP_ERR_INVALID_HEADER,
	BSP_ERR_DECODE_ERROR,
	BSP_ERR_UNIMPLEMENTED,
	BSP_ERR_PATCH_EOF,
	BSP_ERR_FILE_EOF,
	BSP_ERR_NOMEM,
};

/**
 * @brief Opcodes of the BSP virtual machine, one byte each.
 */
// VAR = variable
// HALFWD = halfword
// WD = word
// BT = byte
enum BspOpcode {
	NOP = 0,
	RET,
	JP_WD,
	JP_VAR,
	CALL_WD,
	CALL_VAR,
	EXIT_WD,
	EXIT_VAR,
	PUSH_WD,
	PUSH_VAR,
	POP,
	LENGTH,
	READBT,
	READHALFWD,
	READWD,
	POS,
	GETBT_VAR_WD,
	GETBT_VAR_VAR,
	GETHALFWD_VAR_WD,
	GETHALFWD_VAR_VAR,
	GETWD_VAR_WD,
	GETWD_VAR_VAR,
	CHECKSHA1_VAR_WD,
	CHECKSHA1_VAR_VAR,
	WRITEBT_BT,
	WRITEBT_VAR,
	WRITEHALFWD_HALFWD,
	WRITEHALFWD_VAR,
	WRITEWD_WD,
	WRITEWD_VAR,
	TRUNC_WD,
	TRUNC_VAR,
	ADD_VAR_WD_WD,
	ADD_VAR_WD_VAR,
	ADD_VAR_VAR_WD,
	ADD_VAR_VAR_VAR,
	SUB_VAR_WD_WD,
	SUB_VAR_WD_VAR,
	SUB_VAR_VAR_WD,
	SUB_VAR_VAR_VAR,
	MUL_VAR_WD_WD,
	MUL_VAR_WD_VAR,
	MUL_VAR_VAR_WD,
	MUL_VAR_VAR_VAR,
	DIV_VAR_WD_WD,
	DIV_VAR_WD_VAR,
	DIV_VAR_VAR_WD,
	DIV_VAR_VAR_VAR,
	REM_VAR_WD_WD,
	REM_VAR_WD_VAR,
	REM_VAR_VAR_WD,
	REM_VAR_VAR_VAR,
	AND_VAR_WD_WD,
	AND_VAR_WD_VAR,
	AND_VAR_VAR_WD,
	AND_VAR_VAR_VAR,
	OR_VAR_WD_WD,
	OR_VAR_WD_VAR,
	OR_VAR_VAR_WD,
	OR_VAR_VAR_VAR,
	XOR_VAR_WD_WD,
	XOR_VAR_WD_VAR,
	XOR_VAR_VAR_WD,
	XOR_VAR_VAR_VAR,
	IFLT_VAR_WD_WD,
	IFLT_VAR_WD_VAR,
	IFLT_VAR_VAR_WD,
	IFLT_VAR_VAR_VAR,
	IFLE_VAR_WD_WD,
	IFLE_VAR_WD_VAR,
	IFLE_VAR_VAR_WD,
	IFLE_VAR_VAR_VAR,
	IFGT_VAR_WD_WD,
	IFGT_VAR_WD_VAR,
	IFGT_VAR_VAR_WD,
	IFGT_VAR_VAR_VAR,
	IFGE_VAR_WD_WD,
	IFGE_VAR_WD_VAR,
	IFGE_VAR_VAR_WD,
	IFGE_VAR_VAR_VAR,
	IFEQ_VAR_WD_WD,
	IFEQ_VAR_WD_VAR,
	IFEQ_VAR_VAR_WD,
	IFEQ_VAR_VAR_VAR,
	IFNE_VAR_WD_WD,
	IFNE_VAR_WD_VAR,
	IFNE_VAR_VAR_WD,
	IFNE_VAR_VAR_VAR,
	JUMPZ_VAR_WD,
	JUMPZ_VAR_VAR,
	JUMPNZ_VAR_WD,
	JUMPNZ_VAR_VAR,
	CALLZ_VAR_WD,
	CALLZ_VAR_VAR,
	CALLNZ_VAR_WD,
	CALLNZ_VAR_VAR,
	SEEK_WD,
	SEEK_VAR,
	SEEKFWD_WD,
	SEEKFWD_VAR,
	SEEKBACK_WD,
	SEEKBACK_VAR,
	SEEKEND_WD,
	SEEKEND_VAR,
	PRINT_WD,
	PRINT_VAR,
	MENU_VAR_WD,
	MENU_VAR_VAR,
	XORDATA_WD_WD,
	XORDATA_WD_VAR,
	XORDATA_VAR_WD,
	XORDATA_VAR_VAR,
	FILLBT_WD_BT,
	FILLBT_WD_VAR,
	FILLBT_VAR_BT,
	FILLBT_VAR_VAR,
	FILLHALFWD_WD_HALFWD,
	FILLHALFWD_WD_VAR,
	FILLHALFWD_VAR_HALFWD,
	FILLHALFWD_VAR_VAR,
	FILLWD_WD_WD,
	FILLWD_WD_VAR,
	FILLWD_VAR_WD,
	FILLWD_VAR_VAR,
	WRITEDATA_WD_WD,
	WRITEDATA_WD_VAR,
	WRITEDATA_VAR_WD,
	WRITEDATA_VAR_VAR,
	LOCKPOS,
	UNLOCKPOS,
	TRUNCPOS,
	JUMPTABLE,
	SET_VAR_WD,
	SET_VAR_VAR,
	IPSPATCH_VAR_WD,
	IPSPATCH_VAR_VAR,
	STACKWRITE_WD_WD,
	STACKWRITE_WD_VAR,
	STACKWRITE_VAR_WD,
	STACKWRITE_VAR_VAR,
	STACKREAD_VAR_WD,
	STACKREAD_VAR_VAR,
	STACKSHIFT_WD,
	STACKSHIFT_VAR,
	RETZ,
	RETNZ,
	PUSHPOS,
	POPPOS,
	BSPPATCH_VAR_WD_WD,
	BSPPATCH_VAR_WD_VAR,
	BSPPATCH_VAR_VAR_WD,
	BSPPATCH_VAR_VAR_VAR,
	GETBYTEINC,
	GETHALFWDINC,
	GETWORDINC,
	INCREMENT,
	GETBYTEDEC,
	GETHALFWDDEC,
	GETWORDDEC,
	DECREMENT,
	BUFSTRING_WD,
	BUFSTRING_VAR,
	BUFCHAR_WD,
	BUFCHAR_VAR,
	BUFNUM_WD,
	BUFNUM_VAR,
	PRINTBUF,
	CLEARBUF,
	SETSTACKSIZE_WD,
	SETSTACKSIZE_VAR,
	GETSTACKSIZE,
	BITSHIFT,
	GETFILEBT,
	GETFILEHALFWD,
	GETFILEWD,
	GETVAR,
	ADDCARRY_VAR_VAR_WD_WD,
	ADDCARRY_VAR_VAR_WD_VAR,
	ADDCARRY_VAR_VAR_VAR_WD,
	ADDCARRY_VAR_VAR_VAR_VAR,
	SUBBORROW_VAR_VAR_WD_WD,
	SUBBORROW_VAR_VAR_WD_VAR,
	SUBBORROW_VAR_VAR_VAR_WD,
	SUBBORROW_VAR_VAR_VAR_VAR,
	LMUL_VAR_VAR_WD_WD,
	LMUL_VAR_VAR_WD_VAR,
	LMUL_VAR_VAR_VAR_WD,
	LMUL_VAR_VAR_VAR_VAR,
	LMULAC_VAR_VAR_WD_WD,
	LMULAC_VAR_VAR_WD_VAR,
	LMULAC_VAR_VAR_VAR_WD,
	LMULAC_VAR_VAR_VAR_VAR
};

#endif // BSP_H
