"""
    template_test_harness.py

    Template which loads the context of a process into a Unicorn Engine,
    instance, loads a custom (mutated) inputs, and executes the 
    desired code. Designed to be used in conjunction with one of the
    Unicorn Context Dumper scripts.

    Author:
        Nathan Voss <njvoss299@gmail.com>
"""

import argparse

from unicorn import *
from unicorn.mips_const import *  # TODO: Set correct architecture here as necessary
from textwrap import wrap
import unicorn_loader
import json
import sys

AFTER_RECVFROM = 0x402f80
TMP_CRC32 = 0x402758 

#------------------------
#---- Main test function  


class UnicornRunner():
    def __init__(self, json_data, context_dir, input_data, debug):
        self.json_data = json_data
        self.context_dir = context_dir
        self.input_data = input_data
        self.debug = debug
        self.skip_instructions = json_data['avoid_addresses']
        self.start_address = json_data['start']
        self.end_address = json_data['end']
        
        self.uc = unicorn_loader.AflUnicornEngine(self.context_dir, enable_trace=self.debug, debug_print=False)
        self.unicorn_heap = unicorn_loader.UnicornSimpleHeap(self.uc, debug_print=True)     
    
    def uc_execution_hook(self, uc, address, size, user_data):

        print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size)) 
        if address in self.skip_instructions:
                uc.reg_write(UC_MIPS_REG_PC, address+size)

        if address == AFTER_RECVFROM:
            print ("Skip RECVFROM: 0x{0:08x} and return 0x{1:08x} bytes".format(AFTER_RECVFROM, uc.reg_read(UC_MIPS_REG_V0))) 
    
       
    def set_hooking(self):
        self.uc.hook_add(UC_HOOK_CODE, self.uc_execution_hook)


    def allocate_buffer(self, input_data):
        # Allocate a new buffer and put the input into it
        buf_addr = self.unicorn_heap.malloc(len(input_data))
        self.uc.mem_write(buf_addr, input_data)
        print("Allocated mutated input buffer @ 0x{0:08x}".format(buf_addr))

        # TODO: Set the input into the state so it will be handled
        self.uc.reg_write(UC_MIPS_REG_S3, buf_addr)
        self.uc.reg_write(UC_MIPS_REG_V0, len(input_data))


    def start_forkserver(self):
        # Execute 1 instruction just to startup the forkserver
        # NOTE: This instruction will be executed again later, so be sure that
        #       there are no negative consequences to the overall execution state.
        #       If there are, change the later call to emu_start to no re-execute 
        #       the first instruction.
        print("Starting the forkserver by executing 1 instruction")
        try:
            self.uc.emu_start(self.start_address, 0, 0, count=1)
        except UcError as e:
            print("ERROR: Failed to execute a single instruction (error: {})!".format(e))
            return

    def start(self):
        self.set_hooking()
        self.start_forkserver()
        self.allocate_buffer(self.input_data)
      
        print("Executing from 0x{0:08x} to 0x{1:08x}".format(self.start_address, self.end_address))

        try:
            self.uc.emu_start(self.start_address, self.end_address, timeout=0, count=0)
        except UcError as e:
            # If something went wrong during emulation a signal is raised to force this 
            # script to crash in a way that AFL can detect ('uc.force_crash()' should be
            # called for any condition that you want AFL to treat as a crash).
            print("Execution failed with error: {}".format(e))
            self.uc.dump_regs() 
            self.uc.force_crash(e)

        print("Final register state:")    
        self.uc.dump_regs()

        print("Done.")    


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('json_data_file', type=str, help='Name of json file created by binary ninja ui-afl-unicorn plugin')
    parser.add_argument('context_dir', type=str, help="Directory containing process context")
    parser.add_argument('input_file', type=str, help="Path to the file containing the mutated input content")
    parser.add_argument('-d', '--debug', default=False, action="store_true", help="Dump trace info")
    args = parser.parse_args()

    print("Loading context from {}".format(args.context_dir))
    print("Loading data from {}".format(args.json_data_file))

    # Allocate a buffer and load a mutated input and put it into the right spot
    if args.input_file:
        print("Loading input content from {}".format(args.input_file))
        input_file = open(args.input_file, 'rb')
        input_content = input_file.read()
        encodeData = wrap(input_content,2)
        input_data = ''.join([x.decode('hex') for x in encodeData])
        input_file.close()

        if len(input_data) < 0x10:
            print("Test packet is too small (< {} bytes)".format(0x10))
            return
        elif len(input_data) > 0x10:
            print("Test packet is too big (> {} bytes)".format(0x10))
            return

    if args.json_data_file:
        json_file  = open(args.json_data_file, "r")
        data = json.loads(json_file.read())
        harness_data = {key.encode('utf-8'): value for key, value in data.items()}

    uc_runner = UnicornRunner(harness_data, args.context_dir, input_data, True)
    uc_runner.start()
        
if __name__ == "__main__":
    main()
