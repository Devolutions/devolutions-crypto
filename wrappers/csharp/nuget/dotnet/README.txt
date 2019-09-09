To generate the nuget package :

on windows: 
nuget pack Devolutions.Crypto.nuspec -Version 0.1.1 -OutputDirectory ./package -Properties "platform=windows"

on linux(still requires the windows native libraries): NOT WORKING CURRENTLY ON LINUX - INVESTIGATION NEEDED
nuget pack Devolutions.Crypto.nuspec -Version 0.1.1 -OutputDirectory ./package -Properties "platform=linux"

