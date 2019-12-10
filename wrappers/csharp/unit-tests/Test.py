
from subprocess import check_output
import sys

if sys.argv[1] == "WIN":
    print("Nuget Restore")

    output = check_output(["nuget", "restore", "./dotnet-framework"]).decode(sys.stdout.encoding).strip()
    print(output)

    print("Building Unit tests for DOTNET FRAMEWORK")

    output = check_output(["msbuild.exe", "./dotnet-framework/dotnet-framework.csproj" , "/t:clean,build", "/p:configuration=debug;platform=x64"]).decode(sys.stdout.encoding).strip()
    print(output)

    output= check_output(["msbuild.exe", "./dotnet-framework/dotnet-framework.csproj" , "/t:clean,build", "/p:configuration=debug;platform=x86"]).decode(sys.stdout.encoding).strip()
    print(output)

    print("DOTNET FRAMEWORK UNIT TEST")

    output = check_output(["vstest.console.exe", "./dotnet-framework/bin/x64/Debug/dotnet-framework.dll"]).decode(sys.stdout.encoding).strip()
    print(output)

    if "Test Run Successful" not in output:
        exit(1)

    output = check_output(["vstest.console.exe", "./dotnet-framework/bin/x86/Debug/dotnet-framework.dll"]).decode(sys.stdout.encoding).strip()
    print(output)

    if "Test Run Successful" not in output:
        exit(1)