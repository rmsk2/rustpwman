@echo off
echo *** Building additional tools. Please run this batch file in a Visual Studio developer prompt ***
echo on

cl /EHsc /Ox /MT /W3 paste_utf8.cpp user32.lib
rustc winfilter.rs