# binja-unicorn-afl-plugin
UI Binary Ninja plugin for afl-unicorn 

### If you want to load data to Binary Ninja it expects it as json file with dictionary:

#### a) avoid_addresses is a list of uint addresses
#### b) start is uint start address
#### c) end is uint end address

JSON data: {"start": 0x00402f6c, "end": 0x00402ce8, "avoided_addresses": []}

Data is also saved as json with same format. Save data could be loaded to harness tests of afl-unicorn project

### Introduction video how to use plugin is under link below
https://www.google.com/url?q=https://drive.google.com/file/d/1bLRajQupjlceasrrh8llbNt4GZ7Xq075/view?usp%3Dsharing&sa=D&source=hangouts&ust=1552128568938000&usg=AFQjCNFxYlNRKO9nQsUR9es0xBouAUOXnA