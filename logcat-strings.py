from pwn import *
import sys

if len(sys.argv) != 2:
    print("Usage: python3 logcat-strings.py packagenameorappname")
    sys.exit()

appname=sys.argv[1]

device = adb.wait_for_device()
print("Simple tool to check for interesting strings in ADB logs")
print("===============================================")
print("Device info: ")
print("Arch: "+device.arch)
print("Version: "+device.product)
packages=adb.adb(['shell','pm', 'list', 'packages']).decode('utf-8').split("\n")
packagenames=[]
for package in packages:
    if appname.lower() in package.lower():
       print("[+] Possible package name: "+package.lower().split(":")[1])
       packagenames.append(package.lower().split(":")[1])
print("===============================================")
if len(packagenames) == 1:
   appname=packagenames[0]
commonstrings=["pwd", "password", "hash", "key", "API key", "api","code", "2FA", "token","passwd", "pin", "pincode", "@", "secret", "private", "serial", "logon", "login", "logged", "session", "creds", "credential"]
lines=[]
while True:
      x = adb.logcat().decode('utf-8').split("\n")
      #print(type(x))
      for line in x:
          line=line.lower()
          if appname.lower() in line:
             for i in commonstrings:
                 i=i.lower()
                 if i in line and line not in lines:
                    lines.append(line)
                    print("Match "+i+" :"+line)
