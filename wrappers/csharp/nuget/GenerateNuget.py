import sys
import subprocess
import os
import datetime
import time
import shutil


if len(sys.argv) < 2:
    print("Usage :  python GenerateNuget.py <platform>")
    exit(0)

version = ""

with open('../../../devolutions-crypto/Cargo.toml', 'r') as file:
    data=file.read()
    version = data.split("version = \"")[1].split("\"", 1)[0]

everything = sys.argv[1] == "ALL"

if sys.argv[1] == "WIN" or everything:
    print("Generating WINDOWS nuget...")

    command= subprocess.Popen(["nuget", "pack", "./Windows/Devolutions.Crypto.Windows.nuspec", "-Version", version, "-OutputDirectory", "./Windows/package", "-Properties", "platform=windows"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

if sys.argv[1] == "LINUX" or everything:
    print("Generating LINUX nuget...")

    command= subprocess.Popen(["nuget", "pack", "./Linux/Devolutions.Crypto.Linux.nuspec", "-Version", version, "-OutputDirectory", "./Linux/package", "-Properties", "platform=linux"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

if sys.argv[1] == "IOS" or everything:
    print("Building...")

    command= subprocess.Popen(["msbuild", "./iOS/Devolutions.Crypto.iOS/Devolutions.Crypto.iOS.sln", "/t:clean,build", "/p:configuration=release"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

    if("FAILED" in output):
        exit(1)

    print("Generating IOS nuget...")

    command= subprocess.Popen(["nuget", "pack", "./iOS/Devolutions.Crypto.iOS/Devolutions.Crypto.nuspec", "-Version", version, "-OutputDirectory", "./iOS/Devolutions.Crypto.iOS/package"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

if sys.argv[1] == "MAC-MODERN" or everything:
    print("Building...")

    command= subprocess.Popen(["msbuild", "./macOS/Modern/Devolutions.Crypto.Mac/Devolutions.Crypto.Mac.sln", "/t:clean,build", "/p:configuration=release"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

    if("FAILED" in output):
        exit(1)

    print("Generating MAC MODERN nuget...")

    command= subprocess.Popen(["nuget", "pack", "./macOS/Modern/Devolutions.Crypto.Mac/Devolutions.Crypto.nuspec", "-Version", version, "-OutputDirectory", "./macOS/Modern/Devolutions.Crypto.Mac/package"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

if sys.argv[1] == "MAC-FULL" or everything:
    print("Generating MAC FULL nuget...")

    # platform windows (since the managed mac dll only supports xamarin modern, windows managed dll is compatible)
    command= subprocess.Popen(["nuget", "pack", "./macOS/Full/Devolutions.Crypto.Mac.Full.nuspec", "-Version", version, "-OutputDirectory", "./macOS/Full/package", "-Properties", "platform=windows"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

if sys.argv[1] == "ANDROID" or everything:
    print("Building...")

    command= subprocess.Popen(["msbuild", "./Android/Devolutions.Crypto.Android/Devolutions.Crypto.Android.sln", "/t:clean,build", "/p:configuration=release"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

    if("FAILED" in output):
        exit(1)

    print("Generating ANDROID nuget...")

    command= subprocess.Popen(["nuget", "pack", "./Android/Devolutions.Crypto.Android/Devolutions.Crypto.nuspec", "-Version", version, "-OutputDirectory", "./Android/Devolutions.Crypto.Android/package"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)


if sys.argv[1] == "DOTNET" or everything:
    print("Generating DOTNET CORE nuget...")

    command= subprocess.Popen(["nuget", "pack", "./dotnet-core/Devolutions.Crypto.Core.nuspec", "-Version", version, "-OutputDirectory", "./dotnet-core/package"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)