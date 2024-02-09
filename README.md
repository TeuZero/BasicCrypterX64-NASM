# Basic Crypto X64
# 0xC0FFE
    https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations

[Montei em assembly usando Nasm, usando a peb para achar dll's e funções da API do windows como se fosse um shellcode]

Crypter Básico, esse crypter vai encriptar alguns programas feito em C/C++ e ASM pequenos.

E vai decriptar e executa-lo em um novo processo no caso "svchost.exe".

(Em .NET , VBA,Pascal não funciona.)

Estou usando códigos prontos, pra não perder tempo digitando de novo, caso queria digitar de novo só usar os registradores fazer algumas mudanças adicionando ou removendo códigos, ou usando suas proprias tecnicas, isso para bypass o Anti-Vírus, mas no final vai cumprir a memas função!
foi testado com o programa write.exe encontrado no diretório: "C:\Windows\write.exe" do WINDOWS, com msgbox, com programas de conexão reversa feito em assembly e em C/C++ .

1. Copia o arquivo PE alvo para memória.
2. Vai criptografando e escrevendo o arquivo PE alvo para seção .codered.
3. Salvar o arquivo PE na memoria alocada como arquivo binário, usando fwrite.
4.  O PE encriptado cria o processo svchost.exe da pasta c:\WINDOWS\system32, suspendido.   
5. Descriptografa o arquivo PE alvo na memoria.
6. Se necessario desmapear o endereço base do processo, no caso não precisa, ele só aloca um espaço na memoria no endereço imagebase do processo alvo no svchost.exe
7. faz alguns calculos de relocação de endereço do arquivo PE alvo, e escreve o código começando do endereço IamgeBase até o fim do arquivo.
8. Usa SetThreadContext para setar os endereços.
9. Resumi a thread.  

# Exemplo de compilação:
# nasm -fWin64 T007.asm
# golink /entry:Start /conosle T007.obj


