# binja-unicorn-afl-plugin
UI Binary Ninja plugin for afl-unicorn 

### If you want to load data to Binary Ninja it expects it as json file with dictionary:

#### a) avoid_addresses is a list of uint addresses
#### b) start is uint start address
#### c) end is uint end address

JSON data: {"start": 0x00402f6c, "end": 0x00402ce8, "avoided_addresses": []}

Data is also saved as json with same format. Save data could be loaded to harness tests of afl-unicorn project

#### Sample folder has example ready to run

#### To use plugin put afl_unicorn_plugin.py under Binary Ninja plugins according to OS you have (you can find details on Binary Ninja help pages)

#### core folder is a package with unicorn_loader.py to allow load context data to unicorn

### sample folder include your harness python test file inputs, outputs folder and dumped memory
