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
        return "EXEC FAILED!\n" + result

def main():
    platforms = {
        "framework": test_dotnet_framework,
        "core": test_dotnet_core,
        "ios": test_ios,
        "android": test_android,
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



def test_dotnet_framework(script_dir, version, args):
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


    output = get_output(["vstest.console.exe", "--settings:./dotnet-framework/dotnet-framework.runsettings", "./dotnet-framework/bin/x64/Debug/dotnet-framework.dll"])
    print(output)

    if "Test Run Successful" not in output:
        exit(1)

    output = get_output(["vstest.console.exe", "--settings:./dotnet-framework/dotnet-framework.runsettings", "./dotnet-framework/bin/x86/Debug/dotnet-framework.dll"])
    print(output)

    if "Test Run Successful" not in output:
        exit(1)

def test_dotnet_core(script_dir, version, args):
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

    if "EXEC FAILED!" in output:
        exit(1)


def test_ios(script_dir, version, args):
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

    output = get_output(["msbuild", "./xamarin-ios/xamarin-ios.csproj" , "/t:clean,build", "/p:configuration=debug;platform=iPhoneSimulator"])
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

def test_android(script_dir, version, args):
    print("Nuget Cache Clear")
    print("==========================================================================")    
    
    # CLEAN
    output = get_output(["dotnet", "nuget", "locals", "--clear", "all"], cwd="./xamarin-android")
    print(output)

    print("Remove Local NuGet Source")
    print("==========================================================================")
    output = get_output(["nuget", "sources", "remove", "-Name", "LOCALDEVOCRYPTO"])
    print(output)

    print("Nuget Remove Nuget.org Devolutions.Crypto Package")
    print("==========================================================================")
    output = get_output(["dotnet", "remove", "package", "Devolutions.Crypto.Android"], cwd="./xamarin-android")
    print(output)

    # Restore    
    print("Nuget Restore Global Packages")
    print("==========================================================================")
    output = get_output(["dotnet", "restore", "./xamarin-android", "--verbosity", "normal"])
    print(output)

    print("Add Local NuGet Source")
    print("==========================================================================")
    print(os.path.join(script_dir, "Nugets"))
    output = get_output(["nuget", "sources", "add", "-Name", "LOCALDEVOCRYPTO", "-Source", os.path.join(script_dir, "Nugets")])
    print(output)

    print("Installing Nuget Package in Nugets Source")
    print("==========================================================================")
    
    output = get_output(["nuget", "add", "./Nugets/Devolutions.Crypto.Android." + version + ".nupkg", "-Source", "LOCALDEVOCRYPTO"])
    print(output)

    print("Nuget Add Package Devolutions Crypto to project")
    print("==========================================================================")
    output = get_output(["dotnet", "add", "package", "Devolutions.Crypto.Android", "--source", "../LOCALDEVOCRYPTO", "--version", version], cwd="./xamarin-android")
    print(output)

    print("Building Unit tests for XAMARIN ANDROID")
    print("=========================================================================")
    
    output = get_output(["msbuild", "./xamarin-android/xamarin-android.csproj" , "/t:clean,build,PackageForAndroid,SignAndroidPackage"])
    print(output)
    if("FAILED" in output):
        exit(1)

    print("Installing on emulator")
    output = get_output(["adb", "-s", "emulator-5554", "install", "-r", "./xamarin-android/bin/Debug/xamarin_android.xamarin_android-Signed.apk"])
    print(output)

    print("List instrumentation")
    output = get_output(["adb", "shell", "pm", "list", "instrumentation"])
    print(output)

    print("Running tests")
    output = get_output(["adb", "shell", "am", "instrument", "-w", "xamarin_android.xamarin_android/app.tests.TestInstrumentation"])
    print(output)

    if("INSTRUMENTATION_CODE: -1" not in output):
        exit(1)

if __name__=="__main__":
    main()
