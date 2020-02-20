
import subprocess
import sys

# Current dotnet bugs that prevents this code from being cleanly made
# https://github.com/NuGet/Home/issues/7413 can't specify url as a fallback with local source
# output = get_output(["dotnet", "restore", "--source", "../Nugets", "--source", "https://www.nuget.org/api/v3/", "--verbosity", "normal", "--no-cache", "--force"], cwd="./dotnet-framework")
# --no-cache doesn't work https://github.com/NuGet/Home/issues/5619

def get_output(args, cwd=None):
    try:
        result = subprocess.check_output(args, cwd=cwd, stderr=subprocess.STDOUT).decode(sys.stdout.encoding).strip()
        return result
    except subprocess.CalledProcessError as exc:
        result = exc.output.decode(sys.stdout.encoding).strip()
        return result

version = ""

with open('../../../devolutions-crypto/Cargo.toml', 'r') as filee:
    data=filee.read()
    version = data.split("version = \"")[1].split("\"", 1)[0]

print("Current Devolutions Crypto Version :")
print(version)
print("====================================================================")

if sys.argv[1] == "DOTNET-FRAMEWORK":
    print("Nuget Cache Clear")
    print("==========================================================================")
    
    output = get_output(["dotnet", "nuget", "locals", "--clear", "all"], cwd="./dotnet-framework")
    print(output)

    print("Installing Nuget Package in Nugets folder")
    print("==========================================================================")
    
    output = get_output(["nuget", "add", "./Nugets/Devolutions.Crypto.Windows." + version + ".nupkg", "-Source", "./Nugets"])
    print(output)

    print("Nuget Remove Nuget.org Devolutions.Crypto Package")
    print("==========================================================================")
    output = get_output(["dotnet", "remove", "package", "Devolutions.Crypto.Windows"], cwd="./dotnet-framework")
    print(output)

    print("Nuget Add Package Devolutions Crypto")
    print("==========================================================================")
    output = get_output(["dotnet", "add", "package", "Devolutions.Crypto.Windows", "--source", "../Nugets", "--version", version], cwd="./dotnet-framework")
    print(output)

    print("Nuget Restore Global Packages")
    print("==========================================================================")
    output = get_output(["dotnet", "restore", "./dotnet-framework", "--verbosity", "normal"])
    print(output)

    print("Building Unit tests for DOTNET FRAMEWORK with package config")
    print("=========================================================================")

    output = get_output(["msbuild.exe", "./dotnet-framework/dotnet-framework.csproj" , "/t:clean,build", "/p:configuration=debug;platform=x64"])
    print(output)
    if("FAILED" in output):
        exit(1)

    output= get_output(["msbuild.exe", "./dotnet-framework/dotnet-framework.csproj" , "/t:clean,build", "/p:configuration=debug;platform=x86"])
    print(output)

    if("FAILED" in output):
        exit(1)

    print("DOTNET FRAMEWORK UNIT TEST")
    print("=========================================================================")


    output = get_output(["vstest.console.exe", "./dotnet-framework/bin/x64/Debug/dotnet-framework.dll"])
    print(output)

    if "Test Run Successful" not in output:
        exit(1)

    output = get_output(["vstest.console.exe", "./dotnet-framework/bin/x86/Debug/dotnet-framework.dll"])
    print(output)

    if "Test Run Successful" not in output:
        exit(1)

if sys.argv[1] == "DOTNET-CORE":
    print("Nuget Cache Clear")
    print("==========================================================================")
    
    output = get_output(["dotnet", "nuget", "locals", "--clear", "all"], cwd="./dotnet-core")
    print(output)

    print("Installing Nuget Package in Nugets folder")
    print("==========================================================================")
    
    output = get_output(["nuget", "add", "./Nugets/Devolutions.Crypto.Core." + version + ".nupkg", "-Source", "./Nugets"])
    print(output)

    print("Nuget Remove Nuget.org Devolutions.Crypto Package")
    print("==========================================================================")
    output = get_output(["dotnet", "remove", "package", "Devolutions.Crypto.Core"], cwd="./dotnet-core")
    print(output)

    print("Nuget Add Package Devolutions Crypto")
    print("==========================================================================")
    output = get_output(["dotnet", "add", "package", "Devolutions.Crypto.Core", "--source", "../Nugets", "--version", version], cwd="./dotnet-core")
    print(output)

    print("Nuget Restore Global Packages")
    print("==========================================================================")
    output = get_output(["dotnet", "restore", "./dotnet-core", "--verbosity", "normal"])
    print(output)

    print("Building Unit tests for DOTNET CORE")

    output = get_output(["dotnet", "test", "./dotnet-core"])
    print(output)

    if "Test Run Successful" not in output:
        exit(1)