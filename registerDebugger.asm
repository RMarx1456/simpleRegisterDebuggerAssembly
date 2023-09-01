

section .data
	%DEFINE SYS_MMAP 9
	
	;TODO:
;Add R8-15 registers (done)
;Add XMM/YMM 0-15
;Save register states and return them back to normal after the debugger statement

%MACRO DEBUG_REGISTERS 0
;Saving register values

	MOV [register_states], RAX
	MOV [register_states+1*8], RBX
	MOV [register_states+2*8], RCX
	MOV [register_states+3*8], RDX
	MOV [register_states+4*8], RDI
	MOV [register_states+5*8], RSI
	MOV [register_states+6*8], RBP
	MOV [register_states+7*8], RSP
	MOV [saved_registers], RAX
	MOV [saved_registers+1*8], RBX
	MOV [saved_registers+2*8], RCX
	MOV [saved_registers+3*8], RDX
	MOV [saved_registers+4*8], RDI
	MOV [saved_registers+5*8], RSI
	MOV [saved_registers+6*8], RBP
	MOV [saved_registers+7*8], RSP
	
	MOV [register_states_2+0*8], R8
	MOV [register_states_2+1*8], R9
	MOV [register_states_2+2*8], R10
	MOV [register_states_2+3*8], R11
	MOV [register_states_2+4*8], R12
	MOV [register_states_2+5*8], R13
	MOV [register_states_2+6*8], R14
	MOV [register_states_2+7*8], R15
	MOV [saved_registers_2+0*8], R8
	MOV [saved_registers_2+1*8], R9
	MOV [saved_registers_2+2*8], R10
	MOV [saved_registers_2+3*8], R11
	MOV [saved_registers_2+4*8], R12
	MOV [saved_registers_2+5*8], R13
	MOV [saved_registers_2+6*8], R14
	MOV [saved_registers_2+7*8], R15
	

	;Align stack
	XOR RDX, RDX
	MOV RDI, 0 ;register_hex & register_states pointer
	MOV RSI, 15 ;register_hex char pointer	
	CALL hex_loop
	XOR RDX, RDX
	MOV RDI, 0 ;register_hex & register_states pointer
	MOV RSI, 15 ;register_hex char pointer	
	CALL hex_loop_2

	;RAX
	MOV RAX,  [register_hex+0*8]
	MOV [debugger_statement+PRINT_OFFSET], RAX
	MOV RAX,  [register_hex+1*8]
	MOV [debugger_statement+PRINT_OFFSET_2], RAX
	;RBX
	MOV RAX,  [register_hex+2*8]
	MOV [debugger_statement+PRINT_OFFSET + 1*PRINT_SPACE], RAX
	MOV RAX,  [register_hex+3*8]
	MOV [debugger_statement+PRINT_OFFSET_2 +1*PRINT_SPACE], RAX
	;RCX
	MOV RAX, [register_hex+4*8]
	MOV [debugger_statement+PRINT_OFFSET + 2*PRINT_SPACE], RAX
	MOV RAX, [register_hex+5*8]
	MOV [debugger_statement+PRINT_OFFSET_2 +2*PRINT_SPACE], RAX
	;RDX
	MOV RAX, [register_hex+6*8]
	MOV [debugger_statement+PRINT_OFFSET + 3*PRINT_SPACE], RAX
	MOV RAX, [register_hex+7*8]
	MOV [debugger_statement+PRINT_OFFSET_2 +3*PRINT_SPACE], RAX
	;RDI
	MOV RAX, [register_hex+8*8]
	MOV [debugger_statement+PRINT_OFFSET + 4*PRINT_SPACE], RAX
	MOV RAX, [register_hex+9*8]
	MOV [debugger_statement+PRINT_OFFSET_2 +4*PRINT_SPACE], RAX
	;RSI
	MOV RAX, [register_hex+10*8]
	MOV [debugger_statement+PRINT_OFFSET + 5*PRINT_SPACE], RAX
	MOV RAX, [register_hex+11*8]
	MOV [debugger_statement+PRINT_OFFSET_2 +5*PRINT_SPACE], RAX
	;RBP
	MOV RAX, [register_hex+12*8]
	MOV [debugger_statement+PRINT_OFFSET + 6*PRINT_SPACE], RAX
	MOV RAX, [register_hex+13*8]
	MOV [debugger_statement+PRINT_OFFSET_2 +6*PRINT_SPACE], RAX
	;RSP
	MOV RAX, [register_hex+14*8]
	MOV [debugger_statement+PRINT_OFFSET + 7*PRINT_SPACE], RAX
	MOV RAX, [register_hex+15*8]
	MOV [debugger_statement+PRINT_OFFSET_2 +7*PRINT_SPACE], RAX
	
	;R8
	MOV RAX, [register_hex_2+0*8]
	MOV [debugger_statement_2+PRINT_OFFSET_3 + 0*PRINT_SPACE_2], RAX
	MOV RAX, [register_hex_2+1*8]
	MOV [debugger_statement_2+PRINT_OFFSET_4 +0*PRINT_SPACE_2], RAX
	;R9
	MOV RAX, [register_hex_2+2*8]
	MOV [debugger_statement_2+PRINT_OFFSET_3 + 1*PRINT_SPACE_2], RAX
	MOV RAX, [register_hex_2+3*8]
	MOV [debugger_statement_2+PRINT_OFFSET_4 +1*PRINT_SPACE_2], RAX
	;R10
	MOV RAX, [register_hex_2+4*8]
	MOV [debugger_statement_2+PRINT_OFFSET_3 + 2*PRINT_SPACE_2], RAX
	MOV RAX, [register_hex_2+5*8]
	MOV [debugger_statement_2+PRINT_OFFSET_4 +2*PRINT_SPACE_2], RAX
	;R11
	MOV RAX, [register_hex_2+6*8]
	MOV [debugger_statement_2+PRINT_OFFSET_3 + 3*PRINT_SPACE_2], RAX
	MOV RAX, [register_hex_2+7*8]
	MOV [debugger_statement_2+PRINT_OFFSET_4 +3*PRINT_SPACE_2], RAX
	;R12
	MOV RAX, [register_hex_2+8*8]
	MOV [debugger_statement_2+PRINT_OFFSET_3 + 4*PRINT_SPACE_2], RAX
	MOV RAX, [register_hex_2+9*8]
	MOV [debugger_statement_2+PRINT_OFFSET_4 +4*PRINT_SPACE_2], RAX
	;R13
	MOV RAX, [register_hex_2+10*8]
	MOV [debugger_statement_2+PRINT_OFFSET_3 + 5*PRINT_SPACE_2], RAX
	MOV RAX, [register_hex_2+11*8]
	MOV [debugger_statement_2+PRINT_OFFSET_4 +5*PRINT_SPACE_2], RAX
	;R14
	MOV RAX, [register_hex_2+12*8]
	MOV [debugger_statement_2+PRINT_OFFSET_3 + 6*PRINT_SPACE_2], RAX
	MOV RAX, [register_hex_2+13*8]
	MOV [debugger_statement_2+PRINT_OFFSET_4 +6*PRINT_SPACE_2], RAX
	;R15
	MOV RAX, [register_hex_2+14*8]
	MOV [debugger_statement_2+PRINT_OFFSET_3 + 7*PRINT_SPACE_2], RAX
	MOV RAX, [register_hex_2+15*8]
	MOV [debugger_statement_2+PRINT_OFFSET_4 +7*PRINT_SPACE_2], RAX
	
	
	
	MOV RAX, 1 ;SYS_WRITE
	MOV RDI, 1 ;STDOUT
	MOV RSI, debugger_statement
	MOV RDX, debug_length
	SYSCALL
	MOV RAX, 1 ;SYS_WRITE
	MOV RDI, 1 ;STDOUT
	MOV RSI, debugger_statement_2
	MOV RDX, debug_2_length
	SYSCALL
	
	MOV RAX, [saved_registers+0*8]
	MOV RBX, [saved_registers+1*8]
	MOV RCX, [saved_registers+2*8]
	MOV RDX, [saved_registers+3*8]
	MOV RDI, [saved_registers+4*8]
	MOV RSI, [saved_registers+5*8]
	
	MOV R8, [saved_registers_2+0*8]
	MOV R9, [saved_registers_2+1*8]
	MOV R10, [saved_registers_2+2*8]
	MOV R11, [saved_registers_2+3*8]
	MOV R12, [saved_registers_2+4*8]
	MOV R13, [saved_registers_2+5*8]
	MOV R14, [saved_registers_2+6*8]
	MOV R15, [saved_registers_2+7*8]
	
	
	
	
%ENDMACRO

	;Debugger data
	
	debugger_statement db 'Registers:', 0xA, 'RAX: 0x                ', 0xA, 'RBX: 0x                ', 0xA, 'RCX: 0x                ', 0xA, 'RDX: 0x                ', 0xA, 'RDI: 0x                ', 0xA, 'RSI: 0x                ', 0xA, 'RBP: 0x                ', 0xA, 'RSP: 0x                ', 0xA
	debug_length equ $- debugger_statement
	PRINT_OFFSET equ 18
	PRINT_OFFSET_2 equ 26
	PRINT_SPACE equ 24
	
	debugger_statement_2 db 'R8 : 0x                ', 0xA, 'R9 : 0x                ', 0xA, 'R10: 0x                ', 0xA, 'R11: 0x                ', 0xA, 'R12: 0x                ', 0xA, 'R13: 0x                ', 0xA, 'R14: 0x                ', 0xA, 'R15: 0x                ', 0xA
	debug_2_length equ $- debugger_statement_2
	PRINT_OFFSET_3 equ 7
	PRINT_OFFSET_4 equ 15
	PRINT_SPACE_2 equ 24
	
	register_states dq 0, 0, 0, 0, 0, 0, 0, 0
	saved_registers dq 0, 0, 0, 0, 0, 0, 0, 0
	register_hex dq 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	
	register_states_2 dq 0, 0, 0, 0, 0, 0, 0, 0
	saved_registers_2 dq 0, 0, 0, 0, 0, 0, 0, 0
	register_hex_2 dq 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	
	
	hex_chars db '0123456789ABCDEF'
	NEWLINE db 0xA
	
	        
	
	
section .text

	global _start
	hex_loop:
		MOV RAX, [register_states+EDI*4]
		MOV RBX, 16
		DIV RBX
		MOV [register_states+EDI*4], RAX
		MOV CL, [hex_chars+EDX]
		MOV [register_hex+EDI*8+ ESI], CL
		DEC RSI
		CMP RSI, 0
		JL reset_rsi
		JGE hex_loop
	RET
	reset_rsi:
		ADD RDI, 2
		MOV RSI, 15
		CMP RDI, 16
		JB hex_loop
	RET
	
	hex_loop_2:
		MOV RAX, [register_states_2+EDI*4]
		MOV RBX, 16
		DIV RBX
		MOV [register_states_2+EDI*4], RAX
		MOV CL, [hex_chars+EDX]
		MOV [register_hex_2+EDI*8+ESI], CL
		DEC RSI
		CMP RSI, 0
		JL reset_rsi_2
		JGE hex_loop_2
	RET
	reset_rsi_2:
		ADD RDI, 2
		MOV RSI, 15
		CMP RDI, 16
		JB hex_loop_2
	RET
	
		
	_start:
		MOV RDX, 16
		DEBUG_REGISTERS
	
		MOV RAX, 1
		MOV RDI, 1
		MOV RSI, hex_chars
		MOV RDX, 15
		SYSCALL
		MOV RAX, 1
		MOV RDI, 1
		MOV RSI, NEWLINE
		MOV RDX, 1
		SYSCALL
		MOV R9, 0x000FF23572EE
		DEBUG_REGISTERS
		exit:
			MOV RAX, 60
			XOR RDI, RDI
			SYSCALL
		
		
		
			