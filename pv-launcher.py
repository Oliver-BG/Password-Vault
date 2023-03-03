import os

try:
    os.system('cmd /k "python main.py"')
except:
    print("Could not execute")