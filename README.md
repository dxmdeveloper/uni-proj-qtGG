## Description
Advanced Programming Techniques course project.
A simple chat application with end-to-end encryption.

Server is using PostgreSQL database.
***Author: Maciej Bąbolewski***

### What works
- login and registering
- choosing a conversation from the contact list
- sending and receiving messages (end-to-end encryption)

### What doesn't work (not implemented)
- option menu
- remember me option
- saving messages to a storage
- saving encryption keys

## Features from the assessment list
- thread pool (5 points)
- use of mutex (2 points)
- connection to REST server (3 points)
- REST service (6 points)
- REST authorization and authentication (4 points)
- database (5 points)
- hashing with salt and pepper (7 points)
- static library with a class and methods (3 points)
- DLL dialogs (4 points)
- DLL with classes (4 points)
- 3 dialogs with communication between them (4 points)
- use of symmetric encryption (AES) (2 points)
- use of asymmetric encryption (RSA) (3 points)
- safe updating of the UI from a different thread using Queue (2 points)
### partially implemented
- TCP communication (there is a TCP communication, namely using HTTP, but I don't know if it qualifies) [3 points]
- Use of JSON (only writing and parsing, not deleting) [4 points]
## How to build
### Requirements
- CMake
- C++ 20 compiler and standard libraries
- git (for cloning repositories)
### Windows
If using MSVC, make sure to run `Developer Command Prompt for VS`.

**1. clone the repository and enter the directory**
```
git clone https://github.com/dxmdeveloper/uni-proj-qtGG
cd uni-proj-qtGG
```
**2. clone and install vcpkg**
```
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg integrate install
```
**3. install dependencies**
```
.\vcpkg install nlohmann-json:x64-windows
.\vcpkg install openssl:x64-windows
.\vcpkg install crow:x64-windows
.\vcpkg install qtbase[core,gui,widgets,network,sql]:x64-windows
.\vcpkg install qttools:x64-windows
```
**4. Find and rename method "signals" to "getSignals" in crow's app.h**

**5. build the project**
```
cd ..
mkdir build
cd build
cmake -A=x64 -DCMAKE_TOOLCHAIN_FILE=../vcpkg/scripts/buildsystems/vcpkg.cmake ..
cmake --build .
```
**6. copy DLLs to build binary directory**
- copy content of qtGG-accmgr build folder to qtGG-client build folder
- copy folders from vcpkg/installed/x64-windows/Qt6/plugins to qtGG-client and qtGG-server build folders
- In case you have error opening server: copy dlls (libiconv-2.dll, libintl-8.dll, libpq.dll) from postgresql/bin to qtGG-server build folder
(https://forum.qt.io/topic/134053/qpsql-driver-not-loaded/22)
