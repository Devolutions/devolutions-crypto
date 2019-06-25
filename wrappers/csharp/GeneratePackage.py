import sys
import subprocess
import os
import datetime
import time
import shutil


if len(sys.argv) < 2:
    print("Usage :  python GeneratePakage.py <platform>")
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

    # Compile a DevolutionsCrypto.dll in 32 bit and 64 bit for windows platform
    print("Finding csc compiler...")
    csc_path = ""
        
    command= subprocess.Popen(["where","/r", "c:\\", "csc.exe"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

    if not output or len(output) <= 0:
        print("csc compiler not found!")
        exit()

    paths = output.split("\r\n")

    paths_filtered = []
    for path in paths:
        if("Roslyn" in path):
            paths_filtered.append(path)

    if(len(paths_filtered) == 0):
        print("csc compiler not found!")
        exit()

    csc_path = paths_filtered[0]

    if "csc.exe" not in csc_path:
        print("csc compiler not found!")
        exit()

    print("Found csc compiler!")

    architectures = { "arch" : 
                    [
                        {"name" : "x86", "value" : "i686-pc-windows-msvc"},
                        {"name" : "x64", "value" : "x86_64-pc-windows-msvc"}
                    ]
            }

    try:
        shutil.rmtree("./windows")
    except:
        pass

    os.mkdir("./windows")
    os.mkdir("./windows/bin")

    with open("./windows/bin/AssemblyInfo.cs","w+") as filee:
        filee.write(assembly_manifest)


    for arch in architectures["arch"]:
        print("Starting build for " + arch["name"])

        try:
            shutil.rmtree("../../devolutionscrypto/target/" + arch["value"] + "/release")
        except:
            pass


        print("Building Native Libraries...")

        command= subprocess.Popen(["cargo", "+nightly", "build", "--release", "--target", arch["value"]], cwd="../../devolutionscrypto", stdout=subprocess.PIPE)
        output = command.stdout.read().decode('utf-8')

        print(output)

        os.mkdir("./windows/bin/" + arch["name"])

        shutil.copy("../../devolutionscrypto/target/" + arch["value"] + "/release/devolutionscrypto.dll", "./windows/bin/" + arch["name"] + "/DevolutionsCrypto.dll")

    print("Building Managed Library...")

    command= subprocess.Popen([csc_path,"-out:./windows/bin/Devolutions.Crypto.dll", "-target:library", "-platform:anycpu", "-define:WIN" ,"NativeError.cs", "Native.cs", "ManagedError.cs", "Managed.cs", "KeyExchange.cs", "./windows/bin/AssemblyInfo.cs"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

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

        command= subprocess.Popen(["cargo", "+nightly", "build", "--release", "--target", arch["value"]], cwd="../../devolutionscrypto", stdout=subprocess.PIPE)
        output = command.stdout.read().decode('utf-8')

        print(output)

        os.mkdir("./macos/bin/" + arch["name"])

        shutil.copy("../../devolutionscrypto/target/" + arch["value"] + "/release/libdevolutionscrypto.dylib", "./macos/bin/" + arch["name"] + "/libDevolutionsCrypto.dylib")

    print("Building Managed Library...")
    # TODO create universal library with lipo
    command= subprocess.Popen(["csc", "-out:./macos/bin/Devolutions.Crypto.dll", "-target:library", "-platform:anycpu", "-define:MAC" ,"NativeError.cs", "Native.cs", "ManagedError.cs", "Managed.cs", "KeyExchange.cs", "./macos/bin/AssemblyInfo.cs"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

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

        command= subprocess.Popen(["cargo", "+nightly", "build", "--release", "--target", arch["value"], "--example", "static"], cwd="../../devolutionscrypto", stdout=subprocess.PIPE)
        output = command.stdout.read().decode('utf-8')

        print(output)

        os.mkdir("./ios/bin/" + arch["name"])

        shutil.copy("../../devolutionscrypto/target/" + arch["value"] + "/release/examples/libstatic.a", "./ios/bin/" + arch["name"] + "/libDevolutionsCrypto.a")

    print("Building Managed Library...")
    # TODO create universal library with lipo
    command= subprocess.Popen(["csc", "-out:./ios/bin/Devolutions.Crypto.dll", "-target:library", "-platform:anycpu", "-define:IOS" ,"NativeError.cs", "Native.cs", "ManagedError.cs", "Managed.cs", "KeyExchange.cs", "./ios/bin/AssemblyInfo.cs"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)


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

        command= subprocess.Popen(["cargo", "+nightly", "build", "--release", "--target", arch["value"]], cwd="../../devolutionscrypto", stdout=subprocess.PIPE)
        output = command.stdout.read().decode('utf-8')

        print(output)

        os.mkdir("./android/bin/" + arch["name"])

        shutil.copy("../../devolutionscrypto/target/" + arch["value"] + "/release/libdevolutionscrypto.so", "./android/bin/" + arch["name"] + "/libDevolutionsCrypto.so")

    print("Building Managed Library...")

    command= subprocess.Popen(["csc", "-out:./android/bin/Devolutions.Crypto.dll", "-target:library", "-platform:anycpu", "-define:ANDROID" ,"NativeError.cs", "Native.cs", "ManagedError.cs", "Managed.cs", "KeyExchange.cs", "./android/bin/AssemblyInfo.cs"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)   


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

        command= subprocess.Popen(["cargo", "+nightly", "build", "--release", "--target", arch["value"]], cwd="../../devolutionscrypto", stdout=subprocess.PIPE)
        output = command.stdout.read().decode('utf-8')

        print(output)

        os.mkdir("./linux/bin/" + arch["name"])

        shutil.copy("../../devolutionscrypto/target/" + arch["value"] + "/release/libdevolutionscrypto.so", "./linux/bin/" + arch["name"] + "/libDevolutionsCrypto.so")

    print("Building Managed Library...")

    command= subprocess.Popen(["csc", "-out:./linux/bin/Devolutions.Crypto.dll", "-target:library", "-platform:anycpu", "-define:LINUX" ,"NativeError.cs", "Native.cs", "ManagedError.cs", "Managed.cs", "KeyExchange.cs", "./linux/bin/AssemblyInfo.cs"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

    print("Done")
    exit(0)


