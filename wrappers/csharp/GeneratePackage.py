import sys
import subprocess
import os
import datetime
import time
import shutil


if len(sys.argv) < 2:
    print("Usage :  python GeneratePackage.py <platform>")
    exit(0)

# Assembly manifest template
assembly_manifest = """
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;


[assembly: AssemblyTitle("DevolutionsCrypto")]
[assembly: AssemblyCompany("Devolutions Inc.")]
[assembly: AssemblyCopyright("Copyright ©  ||YEAR||")]

[assembly: AssemblyVersion("||VERSION||")]
"""

print("Generating assembly manifest...")

# Generate assembly manifest with the right version
with open('../../devolutionscrypto/Cargo.toml', 'r') as filee:
    data=filee.read()
    version = data.split("version = \"")[1].split("\"", 1)[0]
    year = data.split("edition = \"")[1].split("\"", 1)[0]
    
    assembly_manifest = assembly_manifest.replace("||YEAR||", year)
    assembly_manifest = assembly_manifest.replace("||VERSION||", version)

if sys.argv[1] == "WIN":
    architectures = { "arch" : 
                    [
                        {"name" : "x86", "value" : "i686-pc-windows-msvc"},
                        {"name" : "x64", "value" : "x86_64-pc-windows-msvc"}
                    ]
            }

    rdm = False

    if(len(sys.argv) >= 3 and sys.argv[2] == "RDM"):
        rdm = True

    folder = "windows"

    if rdm:
        folder = "rdm"

    try:
        shutil.rmtree("./" + folder)
    except:
        pass

    os.mkdir("./" + folder)
    os.mkdir("./" + folder + "/bin")

    with open("./" + folder + "/bin/AssemblyInfo.cs","w+") as filee:
        filee.write(assembly_manifest)

    for arch in architectures["arch"]:
        print("Starting build for " + arch["name"])

        try:
            shutil.rmtree("../../devolutionscrypto/target/" + arch["value"] + "/release")
        except:
            pass


        print("Building Native Libraries...")

        command= subprocess.Popen(["cargo", "build", "--release", "--target", arch["value"]], cwd="../../devolutionscrypto", stdout=subprocess.PIPE)
        output = command.stdout.read().decode('utf-8')

        print(output)
        
        if rdm:
            os.mkdir("./" + folder + "/bin/" + arch["name"])

        dllpath = "./" + folder + "/bin/DevolutionsCrypto-" + arch["name"] + ".dll"

        if rdm:
            dllpath = "./rdm/bin/" + arch["name"] + "/DevolutionsCrypto.dll"

        shutil.copy("../../devolutionscrypto/target/" + arch["value"] + "/release/devolutionscrypto.dll", dllpath)

        command= subprocess.Popen(["./tools/rcedit-x64.exe", dllpath, "--set-file-version", version], stdout=subprocess.PIPE)
        output = command.stdout.read().decode('utf-8')
        print(output)

    print("Building Managed Library...")

    define = "-define:WIN"

    if rdm:
        define += ";RDM"

    command= subprocess.Popen(["csc","-out:./" + folder + "/bin/Devolutions.Crypto.dll", "-debug:pdbonly" ,"-pdb:./" + folder + "/bin/Devolutions.Crypto.pdb", "-target:library", "-platform:anycpu", define ,"NativeError.cs", "Native.cs", "Native.Xamarin.cs", "ManagedError.cs", "Managed.cs", "KeyExchange.cs", "Utils.cs", "Enums.cs", "./" + folder + "/bin/AssemblyInfo.cs"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    if("error" in output):
        exit(1)
        
    print(output)

    os.remove("./" + folder + "/bin/AssemblyInfo.cs")

    print("Done")
    exit(0)

if sys.argv[1] == "MAC":
    architectures = { "arch" : 
                    [
                        #{"name" : "i686", "value" : "i686-apple-darwin"}, # 32 bit no longer supported by mac
                        {"name" : "x86_64", "value" : "x86_64-apple-darwin"}
                    ]
            }

    try:
        shutil.rmtree("./macos")
    except:
        pass

    os.mkdir("./macos")
    os.mkdir("./macos/bin")

    with open("./macos/bin/AssemblyInfo.cs","w+") as filee:
        filee.write(assembly_manifest)


    for arch in architectures["arch"]:
        print("Starting build for " + arch["name"])

        try:
            shutil.rmtree("../../devolutionscrypto/target/" + arch["value"] + "/release")
        except:
            pass


        print("Building Native Libraries...")

        command= subprocess.Popen(["cargo", "build", "--release", "--target", arch["value"]], cwd="../../devolutionscrypto", stdout=subprocess.PIPE)
        output = command.stdout.read().decode('utf-8')

        print(output)

        os.mkdir("./macos/bin/" + arch["name"])

        shutil.copy("../../devolutionscrypto/target/" + arch["value"] + "/release/libdevolutionscrypto.dylib", "./macos/bin/" + arch["name"] + "/libDevolutionsCrypto.dylib")

    print("Building Managed Library...")
    # TODO create universal library with lipo
    command= subprocess.Popen(["csc", "-out:./macos/bin/Devolutions.Crypto.dll", "-debug:pdbonly" ,"-pdb:./macos/bin/Devolutions.Crypto.pdb", "-target:library", "-platform:anycpu", "-define:MAC" ,"NativeError.cs", "Native.cs", "Native.Xamarin.cs", "ManagedError.cs", "Managed.cs", "KeyExchange.cs", "Utils.cs", "Enums.cs", "./macos/bin/AssemblyInfo.cs"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    if("error" in output):
        exit(1)

    print(output)

    os.remove("./macos/bin/AssemblyInfo.cs")

    print("Making universal binary...")

    os.mkdir("./macos/bin/universal")

    libs = []

    for arch in architectures["arch"]:
        libs.append("./macos/bin/" + arch["name"] + "/" + "libDevolutionsCrypto.dylib")
    
    args = ["lipo", "-create"]
    args = args + libs
    args = args + ["-output", "./macos/bin/universal/libDevolutionsCrypto.dylib"]
    
    command= subprocess.Popen(args, stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)


    print("Done")
    exit(0)

if sys.argv[1] == "IOS":
    architectures = { "arch" : 
                [
                    {"name" : "aarch64", "value" : "aarch64-apple-ios"},
                    {"name" : "armv7", "value" : "armv7-apple-ios"},
                    {"name" : "armv7s", "value" : "armv7s-apple-ios"},
                    {"name" : "x86_64", "value" : "x86_64-apple-ios"},
                    {"name" : "i386", "value" : "i386-apple-ios"},
                ]
        }

    try:
        shutil.rmtree("./ios")
    except:
        pass

    os.mkdir("./ios")
    os.mkdir("./ios/bin")

    with open("./ios/bin/AssemblyInfo.cs","w+") as filee:
        filee.write(assembly_manifest)


    for arch in architectures["arch"]:
        print("Starting build for " + arch["name"])

        try:
            shutil.rmtree("../../devolutionscrypto/target/" + arch["value"] + "/release")
        except:
            pass


        print("Building Native Libraries...")

        command= subprocess.Popen(["cargo", "build", "--release", "--target", arch["value"], "--example", "static"], cwd="../../devolutionscrypto", stdout=subprocess.PIPE)
        output = command.stdout.read().decode('utf-8')

        print(output)

        os.mkdir("./ios/bin/" + arch["name"])

        shutil.copy("../../devolutionscrypto/target/" + arch["value"] + "/release/examples/libstatic.a", "./ios/bin/" + arch["name"] + "/libDevolutionsCrypto.a")

    print("Building Managed Library...")
    # TODO create universal library with lipo
    command= subprocess.Popen(["csc", "-out:./ios/bin/Devolutions.Crypto.dll", "-debug:pdbonly" ,"-pdb:./ios/bin/Devolutions.Crypto.pdb", "-target:library", "-platform:anycpu", "-define:IOS" ,"NativeError.cs", "Native.cs", "Native.Xamarin.cs", "ManagedError.cs", "Managed.cs", "KeyExchange.cs", "Utils.cs", "Enums.cs", "./ios/bin/AssemblyInfo.cs"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    if("error" in output):
        exit(1)

    print(output)

    os.remove("./ios/bin/AssemblyInfo.cs")

    print("Making universal binary...")

    os.mkdir("./ios/bin/universal")

    libs = []

    for arch in architectures["arch"]:
        libs.append("./ios/bin/" + arch["name"] + "/" + "libDevolutionsCrypto.a")
    
    args = ["lipo", "-create"]
    args = args + libs
    args = args + ["-output", "./ios/bin/universal/libDevolutionsCrypto.a"]
    
    command= subprocess.Popen(args, stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)
    print("Done")
    exit(0)


if sys.argv[1] == "ANDROID":
    architectures = { "arch" : 
                    [
                        {"name" : "aarch64", "value" : "aarch64-linux-android"},
                        {"name" : "armv7", "value" : "armv7-linux-androideabi"},
                        {"name" : "i686", "value" : "i686-linux-android"},
                        {"name" : "x86_64", "value" : "x86_64-linux-android"}
                    ]
            }

    try:
        shutil.rmtree("./android")
    except:
        pass

    os.mkdir("./android")
    os.mkdir("./android/bin")

    with open("./android/bin/AssemblyInfo.cs","w+") as filee:
        filee.write(assembly_manifest)


    for arch in architectures["arch"]:
        print("Starting build for " + arch["name"])

        try:
            shutil.rmtree("../../devolutionscrypto/target/" + arch["value"] + "/release")
        except:
            pass


        print("Building Native Libraries...")

        command= subprocess.Popen(["cargo", "build", "--release", "--target", arch["value"]], cwd="../../devolutionscrypto", stdout=subprocess.PIPE)
        output = command.stdout.read().decode('utf-8')

        print(output)

        os.mkdir("./android/bin/" + arch["name"])

        shutil.copy("../../devolutionscrypto/target/" + arch["value"] + "/release/libdevolutionscrypto.so", "./android/bin/" + arch["name"] + "/libDevolutionsCrypto.so")

    print("Building Managed Library...")

    command = subprocess.Popen(["csc", "-out:./android/bin/Devolutions.Crypto.dll", "-debug:pdbonly" ,"-pdb:./android/bin/Devolutions.Crypto.pdb", "-target:library", "-platform:anycpu", "-define:ANDROID" ,"NativeError.cs", "Native.cs", "Native.Xamarin.cs", "ManagedError.cs", "Managed.cs", "KeyExchange.cs", "Utils.cs", "Enums.cs", "./android/bin/AssemblyInfo.cs"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    if("error" in output):
        exit(1)

    print(output)   

    os.remove("./android/bin/AssemblyInfo.cs")

    print("Done")
    exit(0)

if sys.argv[1] == "LINUX":
    architectures = { "arch" : 
                [
                    {"name" : "x86_64", "value" : "x86_64-unknown-linux-gnu"},
                    {"name" : "i686", "value" : "i686-unknown-linux-gnu"}
                ]
        }

    try:
        shutil.rmtree("./linux")
    except:
        pass

    os.mkdir("./linux")
    os.mkdir("./linux/bin")

    with open("./linux/bin/AssemblyInfo.cs","w+") as filee:
        filee.write(assembly_manifest)


    for arch in architectures["arch"]:
        print("Starting build for " + arch["name"])

        try:
            shutil.rmtree("../../devolutionscrypto/target/" + arch["value"] + "/release")
        except:
            pass


        print("Building Native Libraries...")

        command= subprocess.Popen(["cargo", "build", "--release", "--target", arch["value"]], cwd="../../devolutionscrypto", stdout=subprocess.PIPE)
        output = command.stdout.read().decode('utf-8')

        print(output)

        archforpackaging = ""

        if(arch["name"] == "i686"):
            archforpackaging = "x86"
        else:
            archforpackaging = "x64"

        shutil.copy("../../devolutionscrypto/target/" + arch["value"] + "/release/libdevolutionscrypto.so", "./linux/bin/libDevolutionsCrypto-" + archforpackaging + ".so")

    print("Building Managed Library...")

    command= subprocess.Popen(["csc", "-out:./linux/bin/Devolutions.Crypto.dll", "-debug:pdbonly" ,"-pdb:./linux/bin/Devolutions.Crypto.pdb", "-target:library", "-platform:anycpu", "-define:LINUX" ,"NativeError.cs", "Native.cs", "Native.Xamarin.cs", "ManagedError.cs", "Managed.cs", "KeyExchange.cs", "Utils.cs", "Enums.cs", "./linux/bin/AssemblyInfo.cs"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    if("error" in output):
        exit(1)

    print(output)

    os.remove("./linux/bin/AssemblyInfo.cs")

    print("Done")
    exit(0)

