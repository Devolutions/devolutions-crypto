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

with open('../../../devolutionscrypto/Cargo.toml', 'r') as file:
    data=file.read()
    version = data.split("version = \"")[1].split("\"", 1)[0]

if sys.argv[1] == "WIN" or sys.argv[1] == "LINUX":
    print("Generating WINDOWS/LINUX nuget...")

    command= subprocess.Popen(["nuget", "pack", "./dotnet/Devolutions.Crypto.nuspec", "-Version", version, "-OutputDirectory", "./dotnet/package", "-Properties", "platform=windows"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

if sys.argv[1] == "IOS":
    print("Building...")

    command= subprocess.Popen(["msbuild", "./iOS/Devolutions.Crypto.iOS/Devolutions.Crypto.iOS.sln", "/t:clean,build", "/p:configuration=release"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

    print("Generating IOS nuget...")

    command= subprocess.Popen(["nuget", "pack", "./iOS/Devolutions.Crypto.iOS/Devolutions.Crypto.nuspec", "-Version", version, "-OutputDirectory", "./iOS/Devolutions.Crypto.iOS/package"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

if sys.argv[1] == "MAC":
    print("Building...")

    command= subprocess.Popen(["msbuild", "./macOS/Devolutions.Crypto.Mac/Devolutions.Crypto.Mac.sln", "/t:clean,build", "/p:configuration=release"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

    print("Generating MAC nuget...")

    command= subprocess.Popen(["nuget", "pack", "./macOS/Devolutions.Crypto.Mac/Devolutions.Crypto.nuspec", "-Version", version, "-OutputDirectory", "./macOS/Devolutions.Crypto.Mac/package"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

if sys.argv[1] == "ANDROID":
    print("Building...")

    command= subprocess.Popen(["msbuild", "./Android/Devolutions.Crypto.Android/Devolutions.Crypto.Android.sln", "/t:clean,build", "/p:configuration=release"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)

    print("Generating ANDROID nuget...")

    command= subprocess.Popen(["nuget", "pack", "./Android/Devolutions.Crypto.Android/Devolutions.Crypto.nuspec", "-Version", version, "-OutputDirectory", "./Android/Devolutions.Crypto.Android/package"], stdout=subprocess.PIPE)
    output = command.stdout.read().decode('utf-8')

    print(output)
