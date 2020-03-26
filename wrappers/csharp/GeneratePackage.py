import argparse
import platform
import sys
import subprocess
import os
import datetime
import time
import shutil
import shlex

# Assembly manifest template
assembly_manifest_template = """
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;


[assembly: AssemblyTitle("DevolutionsCrypto")]
[assembly: AssemblyCompany("Devolutions Inc.")]
[assembly: AssemblyCopyright("Copyright ©  ||YEAR||")]

[assembly: AssemblyVersion("||VERSION||")]
"""

def exec_command(command, cwd="."):
    args = shlex.split(command)
    process = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf8", cwd=cwd)

    output = ""

    if(process.stdout != None):
        output = process.stdout + "\r\n"
    
    if(process.stderr != None):
        output = output + process.stderr
    
    return output

def generate_manifest():
    print("Generating assembly manifest...")
    # Generate assembly manifest with the right version
    with open('../../devolutions-crypto/Cargo.toml', 'r') as file:
        data=file.read()
        version = data.split("version = \"")[1].split("\"", 1)[0]
        
        assembly_manifest = assembly_manifest_template.replace("||YEAR||", str(datetime.datetime.now().year))
        assembly_manifest = assembly_manifest.replace("||VERSION||", version)
    return (assembly_manifest, version)

def build_native(architectures, target_folder, manifest=None):
    try:
        shutil.rmtree(target_folder)
    except:
        pass

    os.mkdir(target_folder)
    os.mkdir(target_folder + "/bin")

    if manifest:
        with open(target_folder + "/bin/AssemblyInfo.cs","w+") as file:
            file.write(manifest)

    for arch in architectures:
        print("Starting build for " + arch["name"])

        try:
            shutil.rmtree("../../devolutions-crypto/target/" + arch["value"] + "/release")
        except:
            pass


        print("Building Native Libraries...")

        command = "cargo build --features ffi --release --target " + arch["value"]
        if arch.get("manifest_path"):
            command = command + " --manifest-path " + arch.get("manifest_path")

        output = exec_command(command, "../../devolutions-crypto")
        print(output)

        os.mkdir(target_folder + "/bin/" + arch["name"])

        shutil.copy(arch["cargo_output"], target_folder + "/bin/" + arch["filename"])

def main():
    platforms = {
        "windows": build_windows,
        "linux": build_linux,
        "mac": build_mac_full,
        "mac-modern": build_mac_modern,
        "ios": build_ios,
        "android": build_android,
    }

    parser = argparse.ArgumentParser()

    parser.add_argument("-p", "--platform", default=platform.system().lower(), 
        choices=platforms.keys(), 
        help="The platform to build for.")

    parser.add_argument("--rdm", action="store_true", default=False, help="Build package for RDM")
    parser.add_argument("-o", "--output", default=None, help="Output folder")

    parser.add_argument("--no-64", action="store_true", default=False, help="Don't build the 64 bit version of the library")
    parser.add_argument("--no-32", action="store_true", default=False, help="Don't build the 32 bit version of the library")
    
    args = parser.parse_args()
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    print("script directory :")
    print(script_dir)

    os.chdir(script_dir)

    (assembly_manifest, version) = generate_manifest()

    platforms.get(args.platform)(assembly_manifest, version, args)
    print("Done")

def build_windows(assembly_manifest, version, args):
    output = exec_command("csc")
    print("output")

    if("is not recognized as an internal or external command" in output):
        print("error : make sure you have csc (c# compiler) configured in your path")
        exit(1)


    architectures = []
    
    if not args.no_32: 
        architectures.append({"name" : "x86", "value" : "i686-pc-windows-msvc"})
        
    if not args.no_64:
        architectures.append({"name" : "x64", "value" : "x86_64-pc-windows-msvc"})

    folder = "windows"

    if args.rdm:
        folder = "rdm"

    # Loop because permission issues on windows
    print("Detecting if " +folder +" directory is present...")
    while(os.path.isdir("./" + folder)):
        print("Deleting " + folder + " directory...")
        try:
            shutil.rmtree("./" + folder)
        except:
            print("Access denied...Retrying")
            time.sleep(1)


    while(not os.path.isdir("./" + folder)):
        try:
            print("Creating " + folder + " directory...")
            os.mkdir("./" + folder)
            os.mkdir("./" + folder + "/bin")
        except:
            print("Access denied...Retrying")
            time.sleep(1)

    with open("./" + folder + "/bin/AssemblyInfo.cs","wb+") as filee:
        filee.write(assembly_manifest.encode("utf-8"))

    for arch in architectures:
        print("Starting build for " + arch["name"])

        try:
            shutil.rmtree("../../devolutions-crypto/target/" + arch["value"] + "/release")
        except:
            pass


        print("Building Native Libraries...")

        output = exec_command("cargo build --features ffi --release --target " + arch["value"], "../../devolutions-crypto")
        print(output)
        
        if args.rdm:
            os.mkdir("./" + folder + "/bin/" + arch["name"])

        dllpath = "./" + folder + "/bin/DevolutionsCrypto-" + arch["name"] + ".dll"

        if args.rdm:
            dllpath = "./rdm/bin/" + arch["name"] + "/DevolutionsCrypto.dll"

        shutil.copy("../../devolutions-crypto/target/" + arch["value"] + "/release/devolutions_crypto.dll", dllpath)

        output = exec_command("./tools/rcedit-x64.exe " + dllpath + " --set-file-version " + version)
        print(output)

    print("Building Managed Library...")

    define = "-define:WIN"

    if args.rdm:
        define += ";RDM"

    output = exec_command("csc -out:./" + folder + "/bin/Devolutions.Crypto.dll -debug:pdbonly -pdb:./" + folder + "/bin/Devolutions.Crypto.pdb -target:library -platform:anycpu " + define + " NativeError.cs Native.cs Native.Xamarin.cs DevolutionsCryptoException.cs Managed.cs KeyPair.cs Utils.cs Enums.cs Enums.Argon2.cs Argon2Parameters.cs ./" + folder + "/bin/AssemblyInfo.cs")
    print(output)

    if("error" in output):
        exit(1)

    os.remove("./" + folder + "/bin/AssemblyInfo.cs")

def build_linux(assembly_manifest, version, args):
    architectures = []
    
    if not args.no_32:
        architectures.append({"name" : "i686", 
            "value" : "i686-unknown-linux-gnu", 
            "cargo_output": "../../devolutions-crypto/target/i686-unknown-linux-gnu/release/libdevolutions_crypto.so", 
            "filename" : "libDevolutionsCrypto-x86.so"})

    if not args.no_64: 
        architectures.append({"name" : "x86_64",
            "value" : "x86_64-unknown-linux-gnu",
            "cargo_output": "../../devolutions-crypto/target/x86_64-unknown-linux-gnu/release/libdevolutions_crypto.so",
            "filename" : "libDevolutionsCrypto-x64.so"})

    target_folder = "./linux"
    if args.output:
        target_folder = args.output

    build_native(architectures, target_folder, manifest=assembly_manifest)

    print("Building Managed Library...")

    output = exec_command("csc -out:./linux/bin/Devolutions.Crypto.dll -debug:pdbonly -pdb:./linux/bin/Devolutions.Crypto.pdb -target:library -platform:anycpu -define:LINUX NativeError.cs Native.cs Native.Xamarin.cs DevolutionsCryptoException.cs Managed.cs KeyPair.cs Utils.cs Enums.cs Enums.Argon2.cs Argon2Parameters.cs ./linux/bin/AssemblyInfo.cs")
    print(output)

    if("error" in output):
        exit(1)    

    os.remove("./linux/bin/AssemblyInfo.cs")

def build_mac_full(assembly_manifest, version, args):
    architectures = [
        #{"name" : "i686", "value" : "i686-apple-darwin"}, # 32 bit no longer supported by mac
        {"name" : "x86_64",
            "value" : "x86_64-apple-darwin",
            "cargo_output": "../../devolutions-crypto/target/x86_64-apple-darwin/release/libdevolutions_crypto.dylib",
            "filename" : "x86_64/libDevolutionsCrypto.dylib"}
    ]

    target_folder = "./macos-full"
    if args.output:
        target_folder = args.output

    build_native(architectures, target_folder, manifest=assembly_manifest)

    print("Building Managed Library...")
    # TODO create universal library with lipo
    output = exec_command("csc -out:./macos-full/bin/Devolutions.Crypto.dll -debug:pdbonly -pdb:./macos-full/bin/Devolutions.Crypto.pdb -target:library -platform:anycpu -define:MAC_FULL NativeError.cs Native.cs Native.Xamarin.cs DevolutionsCryptoException.cs Managed.cs KeyPair.cs Utils.cs Enums.cs Enums.Argon2.cs Argon2Parameters.cs ./macos-full/bin/AssemblyInfo.cs")
    print(output)

    if("error" in output):
        exit(1)    

    os.remove("./macos-full/bin/AssemblyInfo.cs")

    print("Making universal binary...")

    os.mkdir("./macos-full/bin/universal")

    libs = " "

    for arch in architectures:
        libs = libs + " ./macos-full/bin/" + arch["name"] + "/" + "libDevolutionsCrypto.dylib"
    
    args = "lipo -create"
    args = args + libs
    args = args + " -output ./macos-full/bin/universal/libDevolutionsCrypto.dylib"
    
    output = exec_command(args)
    print(output)

    if("error" in output):
        exit(1)

def build_mac_modern(assembly_manifest, version, args):
    architectures = [
        #{"name" : "i686", "value" : "i686-apple-darwin"}, # no longer supported in stable (Tier 3)
        {"name" : "x86_64",
            "value" : "x86_64-apple-darwin",
            "cargo_output": "../../devolutions-crypto/target/x86_64-apple-darwin/release/libdevolutions_crypto.dylib",
            "filename" : "x86_64/libDevolutionsCrypto.dylib"}
    ]

    target_folder = "./macos-modern"
    if args.output:
        target_folder = args.output

    build_native(architectures, target_folder)

    print("Making universal binary...")

    os.mkdir("./macos-modern/bin/universal")

    libs = " "

    for arch in architectures:
        libs = libs + " ./macos-modern/bin/" + arch["name"] + "/" + "libDevolutionsCrypto.dylib"
    
    args = "lipo -create"
    args = args + libs
    args = args + " -output ./macos-modern/bin/universal/libDevolutionsCrypto.dylib"
    
    output = exec_command(args)
    print(output)

    if("error" in output):
        exit(1)

def build_ios(assembly_manifest, version, args):
    architectures = [
        # {"name" : "armv7", "value" : "armv7-apple-ios"}, no longer supported in stable (Tier 3)
        # {"name" : "armv7s", "value" : "armv7s-apple-ios"}, no longer supported in stable (Tier 3)
        # {"name" : "i386", "value" : "i386-apple-ios"}, no longer supported in stable (Tier 3)
        {"name" : "x86_64",
            "value" : "x86_64-apple-ios",
            "manifest_path" : "./ios/Cargo.toml",
            "cargo_output": "../../devolutions-crypto/ios/target/x86_64-apple-ios/release/libdevolutions_crypto.a",
            "filename" : "x86_64/libDevolutionsCrypto.a"},
        {"name" : "aarch64",
            "value" : "aarch64-apple-ios",
            "manifest_path" : "./ios/Cargo.toml",
            "cargo_output": "../../devolutions-crypto/ios/target/aarch64-apple-ios/release/libdevolutions_crypto.a",
            "filename" : "aarch64/libDevolutionsCrypto.a"},
        ]

    target_folder = "./ios"
    if args.output:
        target_folder = args.output

    build_native(architectures, target_folder)

    print("Making universal binary...")

    os.mkdir("./ios/bin/universal")

    libs = " "

    for arch in architectures:
        libs = libs + " ./ios/bin/" + arch["name"] + "/" + "libDevolutionsCrypto.a"
    
    args = "lipo -create "
    args = args + libs
    args = args + " -output ./ios/bin/universal/libDevolutionsCrypto.a"
    
    output = exec_command(args)
    print(output)

    if("error" in output):
        exit(1)

def build_android(assembly_manifest, version, args):
    architectures = [
        {"name" : "aarch64",
            "value" : "aarch64-linux-android",
            "cargo_output": "../../devolutions-crypto/target/aarch64-linux-android/release/libdevolutions_crypto.so",
            "filename" : "aarch64/libDevolutionsCrypto.so"},
        {"name" : "armv7",
            "value" : "armv7-linux-androideabi",
            "cargo_output": "../../devolutions-crypto/target/armv7-linux-androideabi/release/libdevolutions_crypto.so",
            "filename" : "armv7/libDevolutionsCrypto.so"},
        {"name" : "i686",
            "value" : "i686-linux-android",
            "cargo_output": "../../devolutions-crypto/target/i686-linux-android/release/libdevolutions_crypto.so",
            "filename" : "i686/libDevolutionsCrypto.so"},
        {"name" : "x86_64",
            "value" : "x86_64-linux-android",
            "cargo_output": "../../devolutions-crypto/target/x86_64-linux-android/release/libdevolutions_crypto.so",
            "filename" : "x86_64/libDevolutionsCrypto.so"}
    ]

    target_folder = "./android"
    if args.output:
        target_folder = args.output

    build_native(architectures, target_folder)

if __name__=="__main__":
    main()
