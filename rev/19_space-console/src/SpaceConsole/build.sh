#!/bin/sh
dotnet publish
# Zip the output directory
CWD=$(pwd)
cd bin/Release/net9.0/publish
zip $CWD/release.zip *
cd $CWD

