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
        "linux": build_linux,
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

    with open('../config.txt', 'r') as file:
        data=file.read()
        version = data.split("version = \"")[1].split("\"", 1)[0]

    version_live_change()

    platforms.get(args.platform)(version, args)

def version_live_change():
    print("Changing version manifest...")
    # Generate assembly manifest with the right version
    with open('../config.txt', 'r') as file:
        data=file.read()
        version_managed = data.split("version = \"")[1].split("\"", 1)[0]

    with open('../../../Cargo.toml', 'r') as file:
        data=file.read()
        version_native = data.split("version = \"")[1].split("\"", 1)[0]


    with open('../src/Native.cs', 'r+') as file:
        data=file.read()
        file.seek(0)
        data = data.replace("||MANAGED_VERSION||", version_managed)
        data = data.replace("||NATIVE_VERSION||", version_native)
        file.write(data)
        file.truncate()

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

def build_linux(version, args):
    print("Generating LINUX nuget...")

    command= subprocess.Popen(["nuget", "pack", "./Linux/Devolutions.Crypto.Linux.nuspec", "-Version", version, "-OutputDirectory", "./Linux/package", "-Properties", "platform=linux"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

    if("error" in output):
        exit(1)

def build_ios(version, args):
    print("Generating IOS nuget...")

    command= subprocess.Popen(["dotnet", "pack", "./iOS/Devolutions.Crypto.iOS/Devolutions.Crypto.iOS.csproj", "-c", "release", "-p:PackageVersion="+version, "-p:Version=" + version], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

    if("FAILED" in output):
        exit(1)

def build_mac_modern(version, args):
    
    print("Generating MAC nuget...")

    command= subprocess.Popen(["dotnet", "pack", "./macOS/Devolutions.Crypto.Mac/Devolutions.Crypto.Mac.csproj", "-c", "release", "-p:PackageVersion="+version, "-p:Version=" + version], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

    if("error" in output):
        exit(1)

def build_android(version, args):
    print("Generating Android nuget...")

    command= subprocess.Popen(["dotnet", "pack", "./Android/Devolutions.Crypto.Android/Devolutions.Crypto.Mac.csproj", "-c", "release", "-p:PackageVersion="+version, "-p:Version=" + version], stdout=subprocess.PIPE)
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
