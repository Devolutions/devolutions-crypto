To generate the nuget package :

on windows: 
nuget pack Devolutions.Crypto.nuspec -Version 0.1.0 -OutputDirectory ./package -Properties "platform=windows"

on linux(still requires the windows native libraries):
nuget pack Devolutions.Crypto.nuspec -Version 0.1.0 -OutputDirectory ./package -Properties "platform=linux"

