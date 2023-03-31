import argparse
import platform
import subprocess
import sys
import os

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

def main():
    platforms = {
        "ios": test_ios,
    }

    parser = argparse.ArgumentParser()

    parser.add_argument("-p", "--platform", default=platform.system().lower(), 
        choices=platforms.keys(), 
        help="The platform to build for.")

    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    print("script directory :")
    print(script_dir)

    os.chdir(script_dir)

    version = ""

    with open('../../../config.txt', 'r') as filee:
        data=filee.read()
        version = data.split("version = \"")[1].split("\"", 1)[0]

    print("Current Devolutions Crypto Version :")
    print(version)
    print("====================================================================")

    platforms.get(args.platform)(script_dir, version, args)

def test_ios(script_dir, version, args):

    # this test is mostly done to verify that the lib still works with others rust library.
    print("Building Rust Static Lib")
    print("==========================================================================")
    output = get_output(["cargo", "build", "--target", "x86_64-apple-ios", "--release"], cwd="./xamarin-ios/static-rust-lib")
    print(output)


    print("Nuget Cache Clear")
    print("==========================================================================")    
    
    # CLEAN
    output = get_output(["dotnet", "nuget", "locals", "--clear", "all"], cwd="./xamarin-ios")
    print(output)

    print("Remove Local NuGet Source")
    print("==========================================================================")
    output = get_output(["nuget", "sources", "remove", "-Name", "LOCALDEVOCRYPTO"])
    print(output)

    print("Nuget Remove Nuget.org Devolutions.Crypto Package")
    print("==========================================================================")
    output = get_output(["dotnet", "remove", "package", "Devolutions.Crypto.iOS"], cwd="./xamarin-ios")
    print(output)

    # Restore    
    print("Nuget Restore Global Packages")
    print("==========================================================================")
    output = get_output(["dotnet", "restore", "./xamarin-ios", "--verbosity", "normal"])
    print(output)

    print("Add Local NuGet Source")
    print("==========================================================================")
    print(os.path.join(script_dir, "Nugets"))
    output = get_output(["nuget", "sources", "add", "-Name", "LOCALDEVOCRYPTO", "-Source", os.path.join(script_dir, "Nugets")])
    print(output)

    print("Installing Nuget Package in Nugets Source")
    print("==========================================================================")
    
    output = get_output(["nuget", "add", "./Nugets/Devolutions.Crypto.iOS." + version + ".nupkg", "-Source", "LOCALDEVOCRYPTO"])
    print(output)

    # Small hack to fix broken xamarin support
    # If a PackageReference element is not present in the csproj
    # The dotnet add package will fail with an unsupported project error.
    print("hack csproj")

    fixdata = """
    <Reference Include="MonoTouch.NUnitLite" />
  </ItemGroup>
    <ItemGroup>
        <PackageReference Include="Devolutions.Crypto.iOS" Version="*" />
    </ItemGroup>
  """

    filedata = ""
    with open('./xamarin-ios/xamarin-ios.csproj','r') as file:
        filedata = file.read()
        filedata = filedata.replace("""    <Reference Include="MonoTouch.NUnitLite" />
  </ItemGroup>""", fixdata)

    with open('./xamarin-ios/xamarin-ios.csproj','w') as file:
        file.write(filedata)

    print("Nuget Add Package Devolutions Crypto to project")
    print("==========================================================================")
    output = get_output(["dotnet", "add", "package", "Devolutions.Crypto.iOS", "--source", "../LOCALDEVOCRYPTO", "--version", version], cwd="./xamarin-ios")
    print(output)

    # Remove the package reference
    # It will leave the one that was added using dotnet add packge
    filedata = ""
    with open('./xamarin-ios/xamarin-ios.csproj','r') as file:
        filedata = file.read()
        filedata = filedata.replace("""<PackageReference Include="Devolutions.Crypto.iOS" Version="*" />""", "")

    with open('./xamarin-ios/xamarin-ios.csproj','w') as file:
        file.write(filedata)


    print("Building Unit tests for XAMARIN IOS")
    print("=========================================================================")

    # issue with duplicate symbols only happen in Release due to LLVM optimizing compiler
    output = get_output(["msbuild", "./xamarin-ios/xamarin-ios.csproj" , "/t:clean,build", "/p:configuration=Release;platform=iPhoneSimulator"])
    print(output)
    if("FAILED" in output):
        exit(1)

    print("XAMARIN IOS UNIT TEST")
    print("=========================================================================")


    print("Running tests")
    output = get_output(["sh", "./xamarin-ios/test.sh"])
    print(output)

    with open("./xamarin-ios/test_results.xml", "r") as testResult:
        output = testResult.read()
        print(output)
        if "success=\"False\"" in output:
            exit(1)

if __name__=="__main__":
    main()
