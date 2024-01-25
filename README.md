# CrypterBasicInAssemblyX64
Está em desenvolvimento ainda...

 Estou montando aos poucos...::

[Montar em assembly usando Nasm, e usando um pouco de  shellcode]

Crypter Básico (Sim esse crypter vai encriptar seu programa feito em C. em .NET , VBA,Delphi  não testei , o seu programa, o seu .exe e vai injetar em um processo criado do svchost.exe):

Quase tudo pronto.

estou usando códigos prontos, pra não perder tempo digitando de novo, caso queria digitar de novo só usar os registradores fazer algumas mudanças adicionando ou removendo códigos, isso para bypass o Anti-Vírus, mas no final vai cumprir a mesma função!



1. Copiar o arquivo PE do seu programa para um buffer(Variável). (FEITO)
Usando o Buffer:

2. Escrever duas seções com nome de sua escolha. (FEITO)

3. Criar outro buffer que será armazenado o PE alvo de algum programa de sua escolha(por exemplo o bloco de notas). (FEITO)

4. Na seção .TEXT do seu programa escrever o código que vai encriptar o buffer PE do programa alvo que será executado. (FEITO)

5. Copiar o código encriptado para umas das seção que você crio.(FEITO)
6. Escrever o código para criar processo, você vai criar outro Processo do seu próprio processo suspendido. (FEITO)

 7. Escrever um shellcode de conexão no .TEXT do seu programa, encriptalo copiar para outra seção e escrever o decripter do programa alvo nessa mesma seção e o decripter do shellcode também. (JÁ TENHO UM SHELLCODE PARA TESTE MAIS NÃO VOU USAR, VOU FAZER PRIMEIRO A ETAPA 8.).

8. Desmapear e mapear a memoria, Decriptar programa alvo nesse processo limpo, fazer alguns calculos, apontar para entry point e resumi(RunPE). (FEITO)
 Testado em arquivo pequenos.


9. O shellcode encriptado, você vai usar para injetar em algum processo, por exemplo o bloco de notas, então você vai ter que escrever o código de injeção no .TEXT do seu programa ou onde você quiser.. 

10. "Este Programa vai criar um processo, no caso "svchost.exe", depois vai "jogar" o programa passado no começo do programa para o processo suspendido e vai resumi, Detalhes tecnicos vai estar no código."

11. Salvar o buffer como arquivo binário, com entrypoint aleterado. (NÃO FEITO)

# Exemplo de compilação:
# nasm -fWin64 CrypterBasicInAssemblyX64.asm
# golink /entry:Start /conosle CrypterBasicInAssemblyX64.obj


