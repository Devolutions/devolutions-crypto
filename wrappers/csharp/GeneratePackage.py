import sys
import subprocess
import os
import datetime
import time
import shutil

# Compile a DevolutionsCrypto.dll in 32 bit and 64 bit

assembly_manifest = """
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;


[assembly: AssemblyTitle("DevolutionsCrypto")]
[assembly: AssemblyCompany("Devolutions Inc.")]
[assembly: AssemblyCopyright("Copyright ©  ||YEAR||")]

[assembly: AssemblyVersion("||VERSION||")]
"""

print("Finding csharp compiler...")
csc_path = ""
    
command= subprocess.Popen(["where","/r", "c:\\", "csc.exe"], stdout=subprocess.PIPE)
output = command.stdout.read().decode('utf-8')

print(output)

if not output or len(output) <= 0:
    print("csharp compiler not found")
    exit()

paths = output.split("\r\n")

csc_path = paths[0]

if "csc.exe" not in csc_path:
    print("csharp compiler not found")
    exit()

print("Found csharp compiler!")

print("generating manifest")


with open('../../devolutionscrypto/Cargo.toml', 'r') as filee:
    data=filee.read()
    version = data.split("version = \"")[1].split("\"", 1)[0]
    year = data.split("edition = \"")[1].split("\"", 1)[0]
    
    assembly_manifest = assembly_manifest.replace("||YEAR||", year)
    assembly_manifest = assembly_manifest.replace("||VERSION||", version)



architectures = { "arch" : 
                [
                    {"name" : "x86", "value" : "i686-pc-windows-msvc"},
                    {"name" : "x64", "value" : "x86_64-pc-windows-msvc"}
                ]
        }

try:
    shutil.rmtree("./bin")
except:
    pass

os.mkdir("./bin")

with open("./bin/AssemblyInfo.cs","w+") as filee:
    filee.write(assembly_manifest)


for arch in architectures["arch"]:
    print("Starting build for " + arch["name"])

    if not os.path.exists("../../devolutionscrypto/target/" + arch["value"] + "/release/devolutionscrypto.dll"):
        print("Building Native Libraries...")

        command= subprocess.Popen(["cargo", "build", "--release", "--target", arch["value"]], cwd="../../devolutionscrypto", stdout=subprocess.PIPE)
        output = command.stdout.read().decode('utf-8')

        print(output)

    os.mkdir("./bin/" + arch["name"])

    shutil.copy("../../devolutionscrypto/target/" + arch["value"] + "/release/devolutionscrypto.dll", "./bin/" + arch["name"] + "/DevolutionsCryptoNative.dll")

    print("Building Managed Library...")

    command= subprocess.Popen([csc_path,"-out:./bin/" + arch["name"] + "/DevolutionsCrypto.dll", "-target:library","-linkresource:./bin/" + arch["name"] + "/DevolutionsCryptoNative.dll", "-platform:" + arch["name"] ,"DevolutionsCrypto.cs", "./bin/AssemblyInfo.cs"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

    print("Done")              


