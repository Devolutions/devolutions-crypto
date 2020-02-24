import subprocess
import sys
import shutil
import os
import stat
import time

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

with open('../../devolutions-crypto/Cargo.toml', 'r') as filee:
    data=filee.read()
    version = data.split("version = \"")[1].split("\"", 1)[0]

platform = sys.platform

if(platform == "win32" or platform == "win64"):
    print("Building native and managed library")
    print("===================================")
    output = get_output(["python", "./GeneratePackage.py", "WIN"])
    print(output)

    if("Access is denied" in output or "error : make sure you have csc (c# compiler) configured in your path" in output):
        exit(1)

    print("Generating nuget package")
    print("========================")
    output = get_output(["python", "./GenerateNuget.py", "WIN"], cwd="./nuget")
    print(output)

    # Loop because permission issues on windows
    print("Detecting if Nugets directory is present...")
    while(os.path.isdir("./unit-tests/Nugets")):
        print("Deleting Nugets directory...")
        try:
            shutil.rmtree("./unit-tests/Nugets")
        except:
            print("Access denied...Retrying")
            time.sleep(1)

    while(not os.path.isdir("./unit-tests/Nugets")):
        try:
            print("Creating Nugets directory...")
            os.mkdir("./unit-tests/Nugets")
        except:
            print("Access denied...Retrying")
            time.sleep(1)

    shutil.copyfile("./nuget/Windows/package/Devolutions.Crypto.Windows." + version + ".nupkg", "./unit-tests/Nugets/Devolutions.Crypto.Windows." + version + ".nupkg")

    output = get_output(["python", "./Test.py", "DOTNET-FRAMEWORK"], cwd="./unit-tests")
    print(output)



    