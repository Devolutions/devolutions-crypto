
from subprocess import check_output
import sys

if sys.argv[1] == "DOTNET-FRAMEWORK":
    print("Nuget Restore")

    try:
        output = check_output(["dotnet", "restore", "--source", "./Nugets"], cwd="./dotnet-framework").decode(sys.stdout.encoding).strip()
        print(output)
    except Exception as ex:
        print(ex)
        print("this crash is normal")

    output = check_output(["dotnet", "restore", "./dotnet-framework"]).decode(sys.stdout.encoding).strip()
    print(output)

    print("Building Unit tests for DOTNET FRAMEWORK with package config")

    output = check_output(["msbuild.exe", "./dotnet-framework/dotnet-framework.csproj" , "/t:clean,build", "/p:configuration=debug;platform=x64"]).decode(sys.stdout.encoding).strip()
    print(output)

    output= check_output(["msbuild.exe", "./dotnet-framework/dotnet-framework.csproj" , "/t:clean,build", "/p:configuration=debug;platform=x86"]).decode(sys.stdout.encoding).strip()
    print(output)

    print("DOTNET FRAMEWORK with package config UNIT TEST")

    output = check_output(["vstest.console.exe", "./dotnet-framework/bin/x64/Debug/dotnet-framework.dll"]).decode(sys.stdout.encoding).strip()
    print(output)

    if "Test Run Successful" not in output:
        exit(1)

    output = check_output(["vstest.console.exe", "./dotnet-framework/bin/x86/Debug/dotnet-framework.dll"]).decode(sys.stdout.encoding).strip()
    print(output)

    if "Test Run Successful" not in output:
        exit(1)

if sys.argv[1] == "DOTNET-CORE":
    print("Nuget Restore")

    try:
        output = check_output(["dotnet", "restore", "--source", "./Nugets"], cwd="./dotnet-core").decode(sys.stdout.encoding).strip()
        print(output)
    except Exception as ex:
        print(ex)
        print("this crash is normal")

    output = check_output(["dotnet", "restore", "./dotnet-core"]).decode(sys.stdout.encoding).strip()
    print(output)    

    print("Building Unit tests for DOTNET CORE")

    output = check_output(["dotnet", "test", "./dotnet-core"]).decode(sys.stdout.encoding).strip()
    print(output)

    if "Test Run Successful" not in output:
        exit(1)