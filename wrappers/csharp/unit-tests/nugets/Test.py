
import subprocess
import sys
import os

# Current dotnet bugs that prevents this code from being cleanly made
# https://github.com/NuGet/Home/issues/7413 can't specify url as a fallback with local source
# output = get_output(["dotnet", "restore", "--source", "../Nugets", "--source", "https://www.nuget.org/api/v3/", "--verbosity", "normal", "--no-cache", "--force"], cwd="./dotnet-framework")
# --no-cache doesn't work https://github.com/NuGet/Home/issues/5619

script_dir = os.path.dirname(os.path.abspath(__file__))
print("script directory :")
print(script_dir)

os.chdir(script_dir)

def get_output(args, cwd=None):
    try:
        result = subprocess.check_output(args, cwd=cwd, stderr=subprocess.STDOUT).decode(sys.stdout.encoding).strip()
        return result
    except subprocess.CalledProcessError as exc:
        result = exc.output.decode(sys.stdout.encoding).strip()
        return result

version = ""

with open('../../../../devolutions-crypto/Cargo.toml', 'r') as filee:
    data=filee.read()
    version = data.split("version = \"")[1].split("\"", 1)[0]

print("Current Devolutions Crypto Version :")
print(version)
print("====================================================================")

if sys.argv[1] == "DOTNET-FRAMEWORK":
    print("Nuget Cache Clear")
    print("==========================================================================")    
    
    # CLEAN
    output = get_output(["dotnet", "nuget", "locals", "--clear", "all"], cwd="./dotnet-framework")
    print(output)

    print("Remove Local NuGet Source")
    print("==========================================================================")
    output = get_output(["nuget", "sources", "remove", "-Name", "LOCALDEVOCRYPTO"])
    print(output)

    print("Nuget Remove Nuget.org Devolutions.Crypto Package")
    print("==========================================================================")
    output = get_output(["dotnet", "remove", "package", "Devolutions.Crypto.Windows"], cwd="./dotnet-framework")
    print(output)

    # Restore    
    print("Nuget Restore Global Packages")
    print("==========================================================================")
    output = get_output(["dotnet", "restore", "./dotnet-framework", "--verbosity", "normal"])
    print(output)

    print("Add Local NuGet Source")
    print("==========================================================================")
    print(os.path.join(script_dir, "Nugets"))
    output = get_output(["nuget", "sources", "add", "-Name", "LOCALDEVOCRYPTO", "-Source", os.path.join(script_dir, "Nugets")])
    print(output)

    print("Installing Nuget Package in Nugets Source")
    print("==========================================================================")
    
    output = get_output(["nuget", "add", "./Nugets/Devolutions.Crypto.Windows." + version + ".nupkg", "-Source", "LOCALDEVOCRYPTO"])
    print(output)

    print("Nuget Add Package Devolutions Crypto to project")
    print("==========================================================================")
    output = get_output(["dotnet", "add", "package", "Devolutions.Crypto.Windows", "--source", "../LOCALDEVOCRYPTO", "--version", version], cwd="./dotnet-framework")
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
        # CLEAN
    output = get_output(["dotnet", "nuget", "locals", "--clear", "all"], cwd="./dotnet-core")
    print(output)

    print("Remove Local NuGet Source")
    print("==========================================================================")
    output = get_output(["nuget", "sources", "remove", "-Name", "LOCALDEVOCRYPTO"])
    print(output)

    print("Nuget Remove Nuget.org Devolutions.Crypto Package")
    print("==========================================================================")
    output = get_output(["dotnet", "remove", "package", "Devolutions.Crypto.Core"], cwd="./dotnet-core")
    print(output)

    # Restore    
    print("Nuget Restore Global Packages")
    print("==========================================================================")
    output = get_output(["dotnet", "restore", "./dotnet-core", "--verbosity", "normal"])
    print(output)

    print("Add Local NuGet Source")
    print("==========================================================================")
    print(os.path.join(script_dir, "Nugets"))
    output = get_output(["nuget", "sources", "add", "-Name", "LOCALDEVOCRYPTO", "-Source", os.path.join(script_dir, "Nugets")])
    print(output)

    print("Installing Nuget Package in Nugets Source")
    print("==========================================================================")
    
    output = get_output(["nuget", "add", "./Nugets/Devolutions.Crypto.Core." + version + ".nupkg", "-Source", "LOCALDEVOCRYPTO"])
    print(output)

    print("Nuget Add Package Devolutions Crypto to project")
    print("==========================================================================")
    output = get_output(["dotnet", "add", "package", "Devolutions.Crypto.Core", "--source", "../LOCALDEVOCRYPTO", "--version", version], cwd="./dotnet-core")
    print(output)

    print("Building Unit tests for DOTNET CORE")

    output = get_output(["dotnet", "test", "./dotnet-core"])
    print(output)

    if "Test Run Successful" not in output:
        exit(1)

if sys.argv[1] == "XAMARIN-MAC-FULL":
    print("Nuget Cache Clear")
    print("==========================================================================")    
    
    # CLEAN
    output = get_output(["dotnet", "nuget", "locals", "--clear", "all"], cwd="./xamarin-mac-full")
    print(output)

    print("Remove Local NuGet Source")
    print("==========================================================================")
    output = get_output(["nuget", "sources", "remove", "-Name", "LOCALDEVOCRYPTO"])
    print(output)

    print("Nuget Remove Nuget.org Devolutions.Crypto Package")
    print("==========================================================================")
    output = get_output(["dotnet", "remove", "package", "Devolutions.Crypto.Mac.Full"], cwd="./xamarin-mac-full")
    print(output)

    # Restore    
    print("Nuget Restore Global Packages")
    print("==========================================================================")
    output = get_output(["dotnet", "restore", "./xamarin-mac-full", "--verbosity", "normal"])
    print(output)

    print("Add Local NuGet Source")
    print("==========================================================================")
    print(os.path.join(script_dir, "Nugets"))
    output = get_output(["nuget", "sources", "add", "-Name", "LOCALDEVOCRYPTO", "-Source", os.path.join(script_dir, "Nugets")])
    print(output)

    print("Installing Nuget Package in Nugets Source")
    print("==========================================================================")
    
    output = get_output(["nuget", "add", "./Nugets/Devolutions.Crypto.Mac.Full." + version + ".nupkg", "-Source", "LOCALDEVOCRYPTO"])
    print(output)

    print("Nuget Add Package Devolutions Crypto to project")
    print("==========================================================================")
    output = get_output(["dotnet", "add", "package", "Devolutions.Crypto.Mac.Full", "--source", "../LOCALDEVOCRYPTO", "--version", version], cwd="./xamarin-mac-full")
    print(output)

    print("Building Unit tests for XAMARIN MAC FULL")
    print("=========================================================================")

    output = get_output(["msbuild", "./xamarin-mac-full/xamarin-mac-full.csproj" , "/t:clean,build", "/p:configuration=debug;platform=AnyCPU"])
    print(output)
    if("FAILED" in output):
        exit(1)

    print("XAMARIN MAC FULL UNIT TEST")
    print("=========================================================================")

    print("Installing NUnitConsole")
    output = get_output(["wget", "https://github.com/nunit/nunit-console/releases/download/v3.11.1/NUnit.Console-3.11.1.zip"])
    print(output)

    output = get_output(["unzip", "NUnit.Console-3.11.1.zip", "-d", "nunit-console"])
    print(output)

    print("Running tests")
    output = get_output(["mono", "./nunit-console/bin/net35/nunit3-console.exe", "./xamarin-mac-full/bin/Debug/xamarin-mac-full.dll"])
    print(output)

    if "Overall result: Failed" in output:
        exit(1)

if sys.argv[1] == "XAMARIN-MAC-MODERN":
    # Patch submodule for pipeline (MSBuildExtensionsPath is wrong)
    print("patching submodule")
    filedata = ""
    with open('./xamarin-mac-modern/guiunit/src/framework/GuiUnit_xammac_mobile.csproj','r') as file:
        filedata = file.read()
        filedata = filedata.replace("""<Import Project="$(MSBuildExtensionsPath)\Xamarin\Mac\Xamarin.Mac.CSharp.targets" />""", """<Import Project="/Library/Frameworks/Xamarin.Mac.framework/Versions/Current/lib/msbuild/Xamarin.Mac.CSharp.targets" />""")

    with open('./xamarin-mac-modern/guiunit/src/framework/GuiUnit_xammac_mobile.csproj','w') as file:
        file.write(filedata)

    print("Nuget Cache Clear")
    print("==========================================================================")    
    
    # CLEAN
    output = get_output(["dotnet", "nuget", "locals", "--clear", "all"], cwd="./xamarin-mac-modern")
    print(output)

    print("Remove Local NuGet Source")
    print("==========================================================================")
    output = get_output(["nuget", "sources", "remove", "-Name", "LOCALDEVOCRYPTO"])
    print(output)

    print("Nuget Remove Nuget.org Devolutions.Crypto Package")
    print("==========================================================================")
    output = get_output(["dotnet", "remove", "package", "Devolutions.Crypto.Mac.Modern"], cwd="./xamarin-mac-modern")
    print(output)

    # Restore    
    print("Nuget Restore Global Packages")
    print("==========================================================================")
    output = get_output(["dotnet", "restore", "./xamarin-mac-modern", "--verbosity", "normal"])
    print(output)

    print("Add Local NuGet Source")
    print("==========================================================================")
    print(os.path.join(script_dir, "Nugets"))
    output = get_output(["nuget", "sources", "add", "-Name", "LOCALDEVOCRYPTO", "-Source", os.path.join(script_dir, "Nugets")])
    print(output)

    print("Installing Nuget Package in Nugets Source")
    print("==========================================================================")
    
    output = get_output(["nuget", "add", "./Nugets/Devolutions.Crypto.Mac.Modern." + version + ".nupkg", "-Source", "LOCALDEVOCRYPTO"])
    print(output)

    # Small hack to fix broken xamarin support
    # If a PackageReference element is not present in the csproj
    # The dotnet add package will fail with an unsupported project error.
    print("hack csproj")

    fixdata = """
        <Reference Include="Xamarin.Mac" />
  </ItemGroup>
    <ItemGroup>
        <PackageReference Include="Devolutions.Crypto.Mac.Modern" Version="*" />
    </ItemGroup>
  """

    filedata = ""
    with open('./xamarin-mac-modern/xamarin-mac-modern.csproj','r') as file:
        filedata = file.read()
        filedata = filedata.replace("""    <Reference Include="Xamarin.Mac" />
  </ItemGroup>""", fixdata)

    with open('./xamarin-mac-modern/xamarin-mac-modern.csproj','w') as file:
        file.write(filedata)

    print("Nuget Add Package Devolutions Crypto to project")
    print("==========================================================================")
    output = get_output(["dotnet", "add", "package", "Devolutions.Crypto.Mac.Modern", "--source", "../LOCALDEVOCRYPTO", "--version", version], cwd="./xamarin-mac-modern")
    print(output)

    # Remove the package reference
    # It will leave the one that was added using dotnet add packge
    filedata = ""
    with open('./xamarin-mac-modern/xamarin-mac-modern.csproj','r') as file:
        filedata = file.read()
        filedata = filedata.replace("""<PackageReference Include="Devolutions.Crypto.Mac.Modern" Version="*" />""", "")

    with open('./xamarin-mac-modern/xamarin-mac-modern.csproj','w') as file:
        file.write(filedata)

    print("Building Unit tests")
    print("=========================================================================")

    output = get_output(["msbuild", "./xamarin-mac-modern/xamarin-mac-modern.csproj" , "/t:clean,build", "/p:configuration=debug;platform=AnyCPU"])
    print(output)
    if("FAILED" in output):
        exit(1)

    print("UNIT TESTING")
    print("=========================================================================")

    print("Running tests")
    output = get_output(["./xamarin-mac-modern/bin/Debug/xamarin-mac-modern.app/Contents/MacOS/xamarin-mac-modern"])
    print(output)

    if(not os.path.exists("./xamarin-mac-modern/TestResult.xml")):
        print("test result not created assume failed!")
        exit(1)

    with open("./xamarin-mac-modern/TestResult.xml", "r") as testResult:
        output = testResult.read()

        if "success=\"False\"" in output:
            exit(1)