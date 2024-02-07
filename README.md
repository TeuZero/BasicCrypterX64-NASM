# Basic Crypto X64
# 0xC0FFE
    https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations

[Montar em assembly usando Nasm, usando a peb para achar dll's e funções da API do windows como se fosse um shellcode]

Crypter Básico, esse crypter vai encriptar seu programa feito em C/C++ e ASM pequenos.

 (Em .NET , VBA,Pascal não funciona.)

Estou usando códigos prontos, pra não perder tempo digitando de novo, caso queria digitar de novo só usar os registradores fazer algumas mudanças adicionando ou removendo códigos, ou usando suas proprias tecnicas, isso para bypass o Anti-Vírus, mas no final vai cumprir a memas função!
foi testado com o programa write.exe encontrado no diretório: "C:\Windows\write.exe" do WINDOWS, com msgbox, com programas de conexão reversa feito em assembly e em C/C++ .

1. Copia o arquivo PE alvo para memória.
2. Vai criptografando e escrevendo o arquivo PE alvo para seção .codered.
3. Cria o processo svchost.exe da pasta c:\WINDOWS\system32, suspendido.   
4. Descriptografa o arquivo PE alvo na memoria.
5. Se necessario desmapear o endereço base do processo, no caso não precisa, ele só aloca um espaço na memoria no endereço 0x400000 do processo svchost.exe
6. faz alguns calculos de relocação de endereço do arquivo PE alvo, e escreve o código começando do endereço  no 0x400000 até o fim do arquivo.
7. Usa o GetThreadContext e SetThreadContext para setar os endereços.
8. Resumi a thread. 
9. Depois ele abre o proprio arquivo T007.exe, e aloca um endereço com o tamanho do PE ALVO e grava seu PE na memoria.
10. Depois ele copia o código PE alvo encriptado para seção .codered no endereço alocado, faz algumas alterações para pular algumas instruções que já foi executada.
11. Salvar o arquivo PE na memoria alocada como arquivo binário, usando fwrite.

# Exemplo de compilação:
# nasm -fWin64 T007.asm
# golink /entry:Start /conosle T007.obj


