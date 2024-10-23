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
config_path = "./config.txt"

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
    with open(config_path, 'r') as file:
        data=file.read()
        version_managed = data.split("version = \"")[1].split("\"", 1)[0]
        
        assembly_manifest = assembly_manifest_template.replace("||YEAR||", str(datetime.datetime.now().year))
        assembly_manifest = assembly_manifest.replace("||VERSION||", version_managed)
    return (assembly_manifest, version_managed)

def version_live_change():
    print("Changing version manifest...")
    # Generate assembly manifest with the right version
    with open(config_path, 'r') as file:
        data=file.read()
        print(data)
        version_managed = data.split("version = \"")[1].split("\"", 1)[0]

    with open('../../Cargo.toml', 'r') as file:
        data=file.read()
        version_native = data.split("version = \"")[1].split("\"", 1)[0]

    with open('./src/Native.cs', 'r+') as file:
        data=file.read()
        file.seek(0)
        data = data.replace("||MANAGED_VERSION||", version_managed)
        data = data.replace("||NATIVE_VERSION||", version_native)
        file.write(data)
        file.truncate()

def build_native(architectures, target_folder, manifest=None, clean=True):

    if clean:
        try:
            shutil.rmtree(target_folder)
        except:
            pass

    try:
        os.mkdir(target_folder)
    except:
        pass

    try:
        os.mkdir(target_folder + "/bin")
    except:
        pass
    

    if manifest:
        with open(target_folder + "/bin/AssemblyInfo.cs","w+") as file:
            file.write(manifest)

    for arch in architectures:
        print("Starting build for " + arch["name"])

        try:
            shutil.rmtree("../../target/" + arch["value"] + "/release")
        except:
            pass


        print("Building Native Libraries...")

        command = "cargo build --release --target " + arch["value"]
        if arch.get("manifest_path"):
            command = command + " --manifest-path " + arch.get("manifest_path")

        output = exec_command(command, "../../ffi/")
        print(output)

        os.mkdir(target_folder + "/bin/" + arch["name"])

        shutil.copy(arch["cargo_output"], target_folder + "/bin/" + arch["filename"])

def ensure_config():
    if(not os.path.exists(config_path)):
        with open(config_path, "w") as file:
            today = datetime.datetime.today()
            file.write("version = \"" + today.strftime("%Y.%m.%d") + "\"")

def main():
    platforms = {
        "windows": build_windows,
        "dotnet-core": build_dotnet_core,
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

    parser.add_argument("-o", "--output", default=None, help="Output folder")

    parser.add_argument("--no-64", action="store_true", default=False, help="Don't build the 64 bit version of the library")
    parser.add_argument("--no-32", action="store_true", default=False, help="Don't build the 32 bit version of the library")
    
    args = parser.parse_args()

    if(args.platform == "darwin"):
        args.platform = "mac-modern"

    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    print("script directory :")
    print(script_dir)

    os.chdir(script_dir)

    ensure_config()

    (assembly_manifest, version) = generate_manifest()
    version_live_change()

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
        architectures.append({"name" : "arm64", "value" : "aarch64-pc-windows-msvc"})

    folder = "windows"

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
            shutil.rmtree("../../target/" + arch["value"] + "/release")
        except:
            pass


        print("Building Native Libraries...")

        output = exec_command("cargo build --release --target " + arch["value"], "../../ffi")
        print(output)
        
        dllpath = "./" + folder + "/bin/DevolutionsCrypto-" + arch["name"] + ".dll"

        shutil.copy("../../target/" + arch["value"] + "/release/devolutions_crypto_ffi.dll", dllpath)

        output = exec_command("./tools/rcedit-x64.exe " + dllpath + " --set-file-version " + version)
        print(output)

    print("Building Managed Library...")

    define = "-define:WIN"

    output = exec_command("csc -out:./" + folder + "/bin/Devolutions.Crypto.dll -debug:pdbonly -pdb:./" + folder + "/bin/Devolutions.Crypto.pdb -target:library -platform:anycpu " + define + " src/*.cs ./" + folder + "/bin/AssemblyInfo.cs -optimize")
    print(output)

    if("error" in output):
        exit(1)

    os.remove("./" + folder + "/bin/AssemblyInfo.cs")


def build_dotnet_core(assembly_manifest, version, args):
    output = exec_command("csc")
    print("output")

    if("is not recognized as an internal or external command" in output):
        print("error : make sure you have csc (c# compiler) configured in your path")
        exit(1)
    
    folder = "dotnet-core"

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

    print("Building Native Libraries...")

    print("Skipping for .NET Core")      

    print("Building Managed Library...")

    define = "-define:DOTNET_CORE"

    output = exec_command("csc -out:./" + folder + "/bin/Devolutions.Crypto.dll -debug:pdbonly -pdb:./" + folder + "/bin/Devolutions.Crypto.pdb -target:library -platform:anycpu " + define + " src/*.cs ./" + folder + "/bin/AssemblyInfo.cs -optimize")
    print(output)

    if("error" in output):
        exit(1)

    os.remove("./" + folder + "/bin/AssemblyInfo.cs")


def build_linux(assembly_manifest, version, args):
    architectures = []
    
    if not args.no_32:
        architectures.append({"name" : "i686", 
            "value" : "i686-unknown-linux-gnu", 
            "cargo_output": "../../target/i686-unknown-linux-gnu/release/libdevolutions_crypto_ffi.so", 
            "filename" : "libDevolutionsCrypto-x86.so"})

    if not args.no_64: 
        architectures.append({"name" : "x86_64",
            "value" : "x86_64-unknown-linux-gnu",
            "cargo_output": "../../target/x86_64-unknown-linux-gnu/release/libdevolutions_crypto_ffi.so",
            "filename" : "libDevolutionsCrypto-x64.so"})
        
        architectures.append({"name" : "aarch64",
            "value" : "aarch64-unknown-linux-gnu",
            "cargo_output": "../../target/aarch64-unknown-linux-gnu/release/libdevolutions_crypto_ffi.so",
            "filename" : "libDevolutionsCrypto-arm64.so"})

    target_folder = "./linux"
    if args.output:
        target_folder = args.output

    build_native(architectures, target_folder, manifest=assembly_manifest)

    print("Building Managed Library...")

    output = exec_command("csc -out:./linux/bin/Devolutions.Crypto.dll -debug:pdbonly -pdb:./linux/bin/Devolutions.Crypto.pdb -target:library -platform:anycpu -define:LINUX src/*.cs ./linux/bin/AssemblyInfo.cs -optimize")
    print(output)

    if("error" in output):
        exit(1)    

    os.remove("./linux/bin/AssemblyInfo.cs")

def build_mac_full(assembly_manifest, version, args):
    architectures = [
        #{"name" : "i686", "value" : "i686-apple-darwin"}, # 32 bit no longer supported by mac
        {
            "name" : "x86_64",
            "value" : "x86_64-apple-darwin",
            "cargo_output": "../../target/x86_64-apple-darwin/release/libdevolutions_crypto_ffi.dylib",
            "filename" : "x86_64/libDevolutionsCrypto.dylib"
        },
        {
            "name" : "aarch64",
            "value" : "aarch64-apple-darwin",
            "cargo_output": "../../target/aarch64-apple-darwin/release/libdevolutions_crypto_ffi.dylib",
            "filename" : "aarch64/libDevolutionsCrypto.dylib"
        }
    ]

    target_folder = "./macos-full"
    if args.output:
        target_folder = args.output

    build_native(architectures, target_folder, manifest=assembly_manifest, clean=False)

    print("Building Managed Library...")
    output = exec_command("csc -out:./macos-full/bin/Devolutions.Crypto.dll -debug:pdbonly -pdb:./macos-full/bin/Devolutions.Crypto.pdb -target:library -platform:anycpu -define:MAC_FULL src/*.cs ./macos-full/bin/AssemblyInfo.cs -optimize")
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
        {   
            "name" : "x86_64",
            "value" : "x86_64-apple-darwin",
            "cargo_output": "../../target/x86_64-apple-darwin/release/libdevolutions_crypto_ffi.dylib",
            "filename" : "x86_64/libDevolutionsCrypto.dylib"
        },
        {
            "name" : "aarch64",
            "value" : "aarch64-apple-darwin",
            "cargo_output": "../../target/aarch64-apple-darwin/release/libdevolutions_crypto_ffi.dylib",
            "filename" : "aarch64/libDevolutionsCrypto.dylib"
        }
    ]

    target_folder = "./macos-modern"
    if args.output:
        target_folder = args.output

    build_native(architectures, target_folder, clean=False)

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
            "manifest_path" : "./Cargo.toml",
            "cargo_output": "../../target/x86_64-apple-ios/release/libdevolutions_crypto_ffi.dylib",
            "filename" : "x86_64/libDevolutionsCrypto.dylib"},
        {"name" : "aarch64",
            "value" : "aarch64-apple-ios",
            "manifest_path" : "./Cargo.toml",
            "cargo_output": "../../target/aarch64-apple-ios/release/libdevolutions_crypto_ffi.dylib",
            "filename" : "aarch64/libDevolutionsCrypto.dylib"},
        ]

    print("Checking minimum version variable")
    if "IPHONEOS_DEPLOYMENT_TARGET" in os.environ:
        print("IPHONEOS_DEPLOYMENT_TARGET = " + os.getenv("IPHONEOS_DEPLOYMENT_TARGET"))
    else:
        print("Variable IPHONEOS_DEPLOYMENT_TARGET not found!")
        exit(1)

    target_folder = "./ios"
    if args.output:
        target_folder = args.output

    build_native(architectures, target_folder, assembly_manifest)

    print("Making universal binary...")

    os.mkdir("./ios/bin/universal")

    libs = " "

    for arch in architectures:
        libs = libs + " ./ios/bin/" + arch["name"] + "/" + "libDevolutionsCrypto.dylib"
    
    args = "lipo -create "
    args = args + libs
    args = args + " -output ./ios/bin/universal/libDevolutionsCrypto.dylib"
    
    output = exec_command(args)
    print(output)

    if("error" in output):
        exit(1)

    print("Packaging into .framework ...") #########################
    # Unlike .a (static lib) the .dylib needs to be packaged into a .framework package. iOS is now using a dynamic library.

    universal_folder = "./ios/bin/universal/"
    os.mkdir(universal_folder + "libDevolutionsCrypto.framework")
    shutil.move(universal_folder + "libDevolutionsCrypto.dylib", universal_folder + "libDevolutionsCrypto.framework/libDevolutionsCrypto")

    print("Fixing rpath")
    command = subprocess.Popen(["install_name_tool", "-id", "@rpath/libDevolutionsCrypto.framework/libDevolutionsCrypto", universal_folder + "libDevolutionsCrypto.framework/libDevolutionsCrypto"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')
    print(output)

    plist_framework_data = None

    with open("./nuget/iOS/Devolutions.Crypto.iOS/Devolutions.Crypto.iOS/Info.plist", "r") as file:
        plist_framework_data = file.read()

    now = datetime.datetime.now()

    plist_framework_data = plist_framework_data.replace("||VERSION||", version + "." + str(now.hour) + str(now.minute))
    plist_framework_data = plist_framework_data.replace("||SHORT_VERSION||", version)

    with open(universal_folder + "libDevolutionsCrypto.framework/Info.plist", "w+") as file:
        file.write(plist_framework_data)
    ###################################

    print("Building Managed Library...")
    output = exec_command("csc -out:./ios/bin/Devolutions.Crypto.dll -debug:pdbonly -pdb:./ios/bin/Devolutions.Crypto.pdb -target:library -platform:anycpu -define:IOS src/*.cs ./ios/bin/AssemblyInfo.cs -optimize")
    print(output)

    if("error" in output):
        exit(1)    

    os.remove("./ios/bin/AssemblyInfo.cs")


def build_android(assembly_manifest, version, args):
    architectures = [
        {"name" : "aarch64",
            "value" : "aarch64-linux-android",
            "cargo_output": "../../target/aarch64-linux-android/release/libdevolutions_crypto_ffi.so",
            "filename" : "aarch64/libDevolutionsCrypto.so"},
        {"name" : "armv7",
            "value" : "armv7-linux-androideabi",
            "cargo_output": "../../target/armv7-linux-androideabi/release/libdevolutions_crypto_ffi.so",
            "filename" : "armv7/libDevolutionsCrypto.so"},
        {"name" : "i686",
            "value" : "i686-linux-android",
            "cargo_output": "../../target/i686-linux-android/release/libdevolutions_crypto_ffi.so",
            "filename" : "i686/libDevolutionsCrypto.so"},
        {"name" : "x86_64",
            "value" : "x86_64-linux-android",
            "cargo_output": "../../target/x86_64-linux-android/release/libdevolutions_crypto_ffi.so",
            "filename" : "x86_64/libDevolutionsCrypto.so"}
    ]

    target_folder = "./android"
    if args.output:
        target_folder = args.output

    build_native(architectures, target_folder)

if __name__=="__main__":
    main()
