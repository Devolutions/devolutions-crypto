#!/bin/sh
runtime=$(xcrun simctl list runtimes | grep iOS | tail -1 | cut -d ")" -f 2 | cut -d " " -f 3)
deviceType=$(xcrun simctl list devicetypes | grep iPhone | cut -d "(" -f 2 | cut -d ")" -f 1 | grep com | tail -1)
echo $runtime
echo $deviceType
export MONOTOUCH_ROOT=/Library/Frameworks/Xamarin.iOS.framework/Versions/Current

# touch server source https://github.com/prashantvc/Touch.Server/

currentDir=$(/bin/pwd) 

echo $currentDir

TEST_RESULT="${currentDir}/xamarin-ios/test_results.xml"

echo 'Delete test result'

rm -rf $TEST_RESULT
mono --debug ./xamarin-ios/Touch.Server.exe \
--launchsim "${currentDir}/xamarin-ios/bin/iPhoneSimulator/Debug/xamarin-ios.app" \
-autoexit \
-skipheader \
-logfile=$TEST_RESULT \
--verbose \
--device=":v2:runtime=${runtime},devicetype=${deviceType}"
