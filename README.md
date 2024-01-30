# Basic Crypto X64
# 0xC0FFE
    https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations

[Montar em assembly usando Nasm, e usando shellcode]

Crypter Básico, Sim esse crypter vai encriptar seu programa feito em C/C++ e ASM.

 (Em .NET , VBA,Pascal não funciona.)

Estou usando códigos prontos, pra não perder tempo digitando de novo, caso queria digitar de novo só usar os registradores fazer algumas mudanças adicionando ou removendo códigos, ou usando suas proprias tecnicas, isso para bypass o Anti-Vírus, mas no final vai cumprir a memas função!

1. Copiar o arquivo PE do seu programa para um buffer(Variável). 
2. Escrever duas seções com nome de sua escolha. 
3. Criar outro buffer que será armazenado o PE alvo de algum programa pequeno como write.exe encontrado no diretório: "C:\Windows\write.exe", já foi testado com esse programa, com msgbox, com programas de conexão reversa feito em assembly e em C/C++ .
4. Na seção .TEXT do seu programa escrever o código que vai encriptar o buffer PE do programa alvo que será executado. (FEITO)
5. Copiar o código encriptado para umas das seção que você crio.
6. Escrever o código para criar processo do svchost suspendido. 
7. Desmapear e mapear a memoria, fazer alguns calculos, Decriptar programa alvo nesse processo, apontar para entry point e resumi  thread.Testado em programas pequenos,feitos em C/C++ no mingw, Visual Studio, e assembly. (FEITO)
8. Salvar o buffer como arquivo binário. (FEITO)

"Este Programa vai criar um processo, no caso "svchost.exe", depois vai "jogar" o programa passado no começo do programa para o processo suspendido e vai resumi, Detalhes tecnicos vai estar no código."

# Exemplo de compilação:
# nasm -fWin64 T007.asm
# golink /entry:Start /conosle T007.obj


