import argparse
import platform
import sys
import subprocess
import os
import datetime
import time
import shutil

platforms = { }

def main():
    global platforms
    platforms = {
        "all": build_all,
        "windows": build_windows,
        "rdm": build_rdm,
        "linux": build_linux,
        "mac": build_mac_full,
        "mac-modern": build_mac_modern,
        "ios": build_ios,
        "android": build_android,
        "core": build_dotnet_core,
    }

    parser = argparse.ArgumentParser()

    parser.add_argument("-p", "--platform", default=platform.system().lower(), 
        choices=platforms.keys(), 
        help="The platform to build for.")

    parser.add_argument("-o", "--output", default=None, help="Output folder")
    
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    print("script directory :")
    print(script_dir)

    version = ""

    with open('../../../devolutions-crypto/Cargo.toml', 'r') as file:
        data=file.read()
        version = data.split("version = \"")[1].split("\"", 1)[0]

    platforms.get(args.platform)(version, args)

def build_all(version, args):
    for name, handler in platforms.items():
        if name != "all":
            handler(version, args)

def build_windows(version, args):
    print("Generating WINDOWS nuget...")

    command= subprocess.Popen(["nuget", "pack", "./Windows/Devolutions.Crypto.Windows.nuspec", "-Version", version, "-OutputDirectory", "./Windows/package", "-Properties", "platform=windows"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

    if("error" in output):
        exit(1)

def build_rdm(version, args):
    print("Generating WINDOWS RDM nuget...")

    command= subprocess.Popen(["nuget", "pack", "./rdm/Devolutions.Crypto.Windows.RDM.nuspec", "-Version", version, "-OutputDirectory", "./rdm/package"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

    if("error" in output):
        exit(1)

def build_linux(version, args):
    print("Generating LINUX nuget...")

    command= subprocess.Popen(["nuget", "pack", "./Linux/Devolutions.Crypto.Linux.nuspec", "-Version", version, "-OutputDirectory", "./Linux/package", "-Properties", "platform=linux"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

    if("error" in output):
        exit(1)

def build_ios(version, args):
    print("Generating assembly manifest for IOS...")
    # Assembly manifest IOS template
    assembly_manifest_ios = """
    using System.Reflection;
    using System.Runtime.CompilerServices;

    using Foundation;

    [assembly: LinkerSafe]

    [assembly: AssemblyTitle("DevolutionsCrypto")]
    [assembly: AssemblyCompany("Devolutions Inc.")]
    [assembly: AssemblyCopyright("Copyright ©  ||YEAR||")]
    [assembly: AssemblyVersion("||VERSION||")]
    """

    assembly_manifest_ios = assembly_manifest_ios.replace("||YEAR||", str(datetime.datetime.now().year))
    assembly_manifest_ios = assembly_manifest_ios.replace("||VERSION||", version)
    
    if not os.path.exists("./iOS/Devolutions.Crypto.iOS/Devolutions.Crypto.iOS/Properties"):
        os.makedirs("./iOS/Devolutions.Crypto.iOS/Devolutions.Crypto.iOS/Properties")    

    with open("./iOS/Devolutions.Crypto.iOS/Devolutions.Crypto.iOS/Properties/AssemblyInfo.cs","wb+") as filee:
        filee.write(assembly_manifest_ios.encode("utf-8"))

    print("Building...")

    command= subprocess.Popen(["msbuild", "./iOS/Devolutions.Crypto.iOS/Devolutions.Crypto.iOS.sln", "/t:clean,restore,build", "/p:configuration=release"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

    if("FAILED" in output):
        exit(1)

    print("Generating IOS nuget...")

    command= subprocess.Popen(["nuget", "pack", "./iOS/Devolutions.Crypto.iOS/Devolutions.Crypto.iOS.nuspec", "-Version", version, "-OutputDirectory", "./iOS/Devolutions.Crypto.iOS/package"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

    if("error" in output):
        exit(1)

def build_mac_modern(version, args):
    print("Generating assembly manifest for MAC MODERN...")
    # Assembly manifest Mac Modern template
    assembly_manifest_mac_modern = """
    using System.Reflection;
    using System.Runtime.CompilerServices;

    using Foundation;

    [assembly: LinkerSafe]

    [assembly: AssemblyTitle("DevolutionsCrypto")]
    [assembly: AssemblyCompany("Devolutions Inc.")]
    [assembly: AssemblyCopyright("Copyright ©  ||YEAR||")]

    [assembly: AssemblyVersion("||VERSION||")]
    """

    assembly_manifest_mac_modern = assembly_manifest_mac_modern.replace("||YEAR||", str(datetime.datetime.now().year))
    assembly_manifest_mac_modern = assembly_manifest_mac_modern.replace("||VERSION||", version)

    if not os.path.exists("./macOS/Modern/Devolutions.Crypto.Mac/Devolutions.Crypto.Mac/Properties"):
        os.makedirs("./macOS/Modern/Devolutions.Crypto.Mac/Devolutions.Crypto.Mac/Properties")    

    with open("./macOS/Modern/Devolutions.Crypto.Mac/Devolutions.Crypto.Mac/Properties/AssemblyInfo.cs","wb+") as filee:
        filee.write(assembly_manifest_mac_modern.encode("utf-8"))

    print("Building...")

    command= subprocess.Popen(["msbuild", "./macOS/Modern/Devolutions.Crypto.Mac/Devolutions.Crypto.Mac.sln", "/t:clean,restore,build", "/p:configuration=release"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

    if("FAILED" in output):
        exit(1)

    print("Generating MAC MODERN nuget...")

    command= subprocess.Popen(["nuget", "pack", "./macOS/Modern/Devolutions.Crypto.Mac/Devolutions.Crypto.Mac.Modern.nuspec", "-Version", version, "-OutputDirectory", "./macOS/Modern/Devolutions.Crypto.Mac/package"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

    if("error" in output):
        exit(1)

def build_mac_full(version, args):
    print("Generating MAC FULL nuget...")

    # platform windows (since the managed mac dll only supports xamarin modern, windows managed dll is compatible)
    command= subprocess.Popen(["nuget", "pack", "./macOS/Full/Devolutions.Crypto.Mac.Full.nuspec", "-Version", version, "-OutputDirectory", "./macOS/Full/package"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

    if("error" in output):
        exit(1)

def build_android(version, args):
    print("Generating assembly manifest for Android...")
    # Assembly manifest Android template
    assembly_manifest_android = """
    using System.Reflection;
    using System.Runtime.CompilerServices;
    using System.Runtime.InteropServices;
    using Android.App;

    [assembly: AssemblyTitle("DevolutionsCrypto")]
    [assembly: AssemblyCompany("Devolutions Inc.")]
    [assembly: AssemblyCopyright("Copyright ©  ||YEAR||")]

    [assembly: AssemblyVersion("||VERSION||")]
    
    [assembly: ComVisible(false)]
    """

    assembly_manifest_android = assembly_manifest_android.replace("||YEAR||", str(datetime.datetime.now().year))
    assembly_manifest_android = assembly_manifest_android.replace("||VERSION||", version)

    if not os.path.exists("./Android/Devolutions.Crypto.Android/Devolutions.Crypto.Android/Properties"):
        os.makedirs("./Android/Devolutions.Crypto.Android/Devolutions.Crypto.Android/Properties")    

    with open("./Android/Devolutions.Crypto.Android/Devolutions.Crypto.Android/Properties/AssemblyInfo.cs","wb+") as filee:
        filee.write(assembly_manifest_android.encode("utf-8"))

    print("Building...")

    command= subprocess.Popen(["msbuild", "./Android/Devolutions.Crypto.Android/Devolutions.Crypto.Android.sln", "/t:clean,restore,build", "/p:configuration=release"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

    if("FAILED" in output):
        exit(1)

    print("Generating ANDROID nuget...")

    command= subprocess.Popen(["nuget", "pack", "./Android/Devolutions.Crypto.Android/Devolutions.Crypto.Android.nuspec", "-Version", version, "-OutputDirectory", "./Android/Devolutions.Crypto.Android/package"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

    if("error" in output):
        exit(1)

def build_dotnet_core(version, args):
    print("Generating DOTNET CORE nuget...")

    command= subprocess.Popen(["nuget", "pack", "./dotnet-core/Devolutions.Crypto.Core.nuspec", "-Version", version, "-OutputDirectory", "./dotnet-core/package"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)
    if("error" in output):
        exit(1)

if __name__=="__main__":
    main()
