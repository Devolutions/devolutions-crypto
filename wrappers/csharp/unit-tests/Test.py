
from subprocess import check_output
import sys

if sys.argv[1] == "DOTNET-FRAMEWORK-PACKAGE-CONFIG":
    print("Nuget Restore")

    output = check_output(["nuget", "restore", "./dotnet-framework-package-config"]).decode(sys.stdout.encoding).strip()
    print(output)

    print("Building Unit tests for DOTNET FRAMEWORK with package config")

    output = check_output(["msbuild.exe", "./dotnet-framework-package-config/dotnet-framework.csproj" , "/t:clean,build", "/p:configuration=debug;platform=x64"]).decode(sys.stdout.encoding).strip()
    print(output)

    output= check_output(["msbuild.exe", "./dotnet-framework-package-config/dotnet-framework.csproj" , "/t:clean,build", "/p:configuration=debug;platform=x86"]).decode(sys.stdout.encoding).strip()
    print(output)

    print("DOTNET FRAMEWORK with package config UNIT TEST")

    output = check_output(["vstest.console.exe", "./dotnet-framework-package-config/bin/x64/Debug/dotnet-framework.dll"]).decode(sys.stdout.encoding).strip()
    print(output)

    if "Test Run Successful" not in output:
        exit(1)

    output = check_output(["vstest.console.exe", "./dotnet-framework-package-config/bin/x86/Debug/dotnet-framework.dll"]).decode(sys.stdout.encoding).strip()
    print(output)

    if "Test Run Successful" not in output:
        exit(1)

if sys.argv[1] == "DOTNET-CORE":
    print("Nuget Restore")

    output = check_output(["nuget", "restore", "./dotnet-framework-package-config"]).decode(sys.stdout.encoding).strip()
    print(output)

    print("Building Unit tests for DOTNET CORE")

    output = check_output(["dotnet", "test"]).decode(sys.stdout.encoding).strip()
    print(output)

    if "Test Run Successful" not in output:
        exit(1)