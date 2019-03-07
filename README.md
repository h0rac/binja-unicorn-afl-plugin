# binja-unicorn-afl-plugin
UI Binary Ninja plugin for afl-unicorn 

### If you want to load data to Binary Ninja it expects it as json file with dictionary:

#### a) avoid_addresses is a list of uint addresses
#### b) start is uint start address
#### c) end is uint end address

JSON data: {"start": 0x00402f6c, "end": 0x00402ce8, "avoided_addresses": []}

Data is also saved as json with same format. Save data could be loaded to harness tests of afl-unicorn project