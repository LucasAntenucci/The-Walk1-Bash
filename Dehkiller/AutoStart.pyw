import subprocess
from subprocess import CREATE_NO_WINDOW
import pathlib
import atexit
from ctypes import *

caminhob = str(input("Insira o caminho da pasta que deseja realizar o Backup: "))
subprocess.Popen(r'robocopy {} E: /e /copyall'.format(caminhob))
subprocess.Popen(r'C:\Dehkiller\remove.cmd')

drive = pathlib.Path.home().drive
py_path = drive + "\\Dehkiller\\Dehkiller.exe -l -r " + drive +  "\\Dehkiller\\ransom.yar -k"
try:
   pid = subprocess.Popen(py_path, creationflags=CREATE_NO_WINDOW)
   print("[MEMORY-SCANNER] Sucesso ao abrir o Memory-Scanner!")
except Exception as e:
   erro = f"Erro ao abrir o Memory Scanner: {e}"
   windll.user32.MessageBoxA(0, erro.encode(), b"ALERTA!!!", 0)

def killDehkiller(dehkiller):
    try:
       dehkiller.kill()
       print("[MEMORY-SCANNER] Finalizando o Memory Scanner...")
    except Exception as e:
        print("[MEMORY-SCANNER] Falha ao finalizar o Memory Scanner.")








 
       


