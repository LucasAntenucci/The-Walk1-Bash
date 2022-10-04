import subprocess
import re
import time
import pyfiglet
import os
import yara
import atexit
import pathlib
import optparse
from ctypes import *
from ctypes import wintypes
import re

os.system('cls' if os.name == 'nt' else 'clear')
ascii_banner1 = pyfiglet.figlet_format("Dehrekkis")
print(ascii_banner1)
print("By The Walk1 Bash ")

time.sleep(1)


def PrintBanner():
    return """

                        FIAP                                                        Pride  Security

*============:   *.           =*=           -*============.                .::-===:                  .==--:..
# .               *:          +- -*          -+            +=            .:-========+.              .+=========-:
# .               *:        .*:   :*.        -+            .#            ===========+.               +==========+
# .               *:       :*.     .*-       -+            +=            ===========+.               +===========
# .  .-----.      *:      =+         -.      -+    -----===:             ===========+                +===========
# .               *:     +-                  -+                          -==========+                ===========-
# .               *:   .+:             :*.   -+                          :==========+                ===========.
# .               *:  :+.               .+:  -+                           ==========+                +==========
                                                                          +========+                +=========
                                                                            ========.               .========
                                                                             =======:               :======
                                                                               ======               ======
                                                                                 ====  :::::::::::  ====
                                                                                      :-: =++++=.:-:
"""


PrintBanner()
print(PrintBanner())
time.sleep(1)

print("1 = Executar a DEHA  ")
print("2 = Executar o Dehkiller  \n")
escolha = int(input("Qual programa vc deseja executar : "))


def yara_analise():

    os.system('cls' if os.name == 'nt' else 'clear')
    caminho = input(
        "Insira o caminho do arquivo para analise : ")

    yara_output = subprocess.check_output(
        r'C:\Dehkiller\yara64.exe -w -r C:\Dehkiller\rules-master\index.yar ' + caminho, shell=True).decode()

    with open("Analise_yara.txt", "w") as arquivo:
        arquivo.write(yara_output)

    arquivo = open("Analise_yara.txt", "r")
    linhas = arquivo.readlines()

    yara_output_list = []

    index = 0
    for item in linhas:
        if not item == "\n":
            index = index + 1
            print(f"{index} - {item}")
            yara_output_list.append(item)

    if yara_output == "":
        print("Arquivo limpo...")

    else:
        print("Possivel arquivo malicioso...")
        print("Apagando o arquivo...")
        os.remove(caminho)

    time.sleep(1)
    input("digite ENTER para sair...")


if escolha == 1:

    yara_analise()


if escolha == 2:

    os.system('cls' if os.name == 'nt' else 'clear')
    modo = int(
        input("1 = Abrir manualmente a ferramenta\n2 = Acompanhar logs\n\n"))
    if modo == 1:
        regras = str(input("Insira um arquivo com regras: \n"))

        os.system('cls' if os.name == 'nt' else 'clear')

        opcao = int(input(
            "1 = proteção em tempo real ou\n2 = PID específico\n"))

        os.system('cls' if os.name == 'nt' else 'clear')

        kill = int(
            input("1 = matar processos na memoria\n"))
        if opcao == 2:
            pid = int(input("Qual PID? "))

        rules = " -r " + regras
        if kill == 1:
            kill = " -k "
        else:
            kill = None

        if opcao == 1:
            opcao = " -l "
        else:
            opcao = " -p " + pid
        try:
            os.system('cls' if os.name == 'nt' else 'clear')

            memscanner = subprocess.Popen(
                "Dehkiller.exe "+ opcao + " " + rules + " " + kill)

        except Exception as e:
            print(f"Error: {e}")

    if modo == 2:
        os.system('cls' if os.name == 'nt' else 'clear')

        drive = pathlib.Path.home().drive
        index = 0
        while True:
            with open(drive+"\\Dehkiller\\memorylog", "r") as logs:
                readlogs = logs.read().splitlines()

            try:
                print(readlogs[index])
                index += 1
            except:
                continue
