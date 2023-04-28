## Dyld-DeNeuralyzer

A simple set of POCs to demonstrate in-memory loading of Mach-O's like Wechat or something, so that you can do remote injection.

* Patch up dyld for in-memory loading of Mach-O bundles.

## Usage

```
//backup exe
mv /Applications/WeChat.app/Contents/MacOS/WeChat /Applications/WeChat.app/Contents/MacOS/Backup

//move loader to exe path
cp ./DyldDeNeuralyzer /Applications/WeChat.app/Contents/MacOS/Wechat 

//check codesign
codesign -vvd /Applications/WeChat.app/Contents/MacOS/WeChat

//run wechat
/Applications/WeChat.app/Contents/MacOS/WeChat

/*
module name=/private/var/folders/b1/0fd1b6hs7lz0fm_mh346lybm0000gn/T/NSCreateObjectFileImageFromMemory-dCPkDRql
Invoking loaded function at 0x110d74324(10fb80000+11f4324)... hold onto your butts....!!
*/

//restore exe
mv /Applications/WeChat.app/Contents/MacOS/Backup /Applications/WeChat.app/Contents/MacOS/WeChat

//check codesign
codesign -vvd /Applications/WeChat.app/Contents/MacOS/WeChat
```
