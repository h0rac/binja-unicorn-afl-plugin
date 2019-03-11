"""
    template_test_harness.py

    Template which loads the context of a process into a Unicorn Engine,
    instance, loads a custom (mutated) inputs, and executes the 
    desired code. Designed to be used in conjunction with one of the
    Unicorn Context Dumper scripts.

    Author:
        Nathan Voss <njvoss299@gmail.com> Modified by h0rac to support UI binaryninja plugin
"""

import argparse

from unicorn import *
from unicorn.mips_const import *  # TODO: Set correct architecture here as necessary
from textwrap import wrap
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
from core import unicorn_loader 
import json

# Simple stand-in heap to prevent OS/kernel issues
unicorn_heap = None

#------------------------
#---- Main test function  

def main():

      
    parser = argparse.ArgumentParser()
    parser.add_argument('json_data_file', type=str, help="JSON data from afl-unicorn binaryninja plugin")
    parser.add_argument('context_dir', type=str, help="Directory containing process context")
    parser.add_argument('input_file', type=str, help="Path to the file containing the mutated input content")
    parser.add_argument('-d', '--debug', default=False, action="store_true", help="Dump trace info")
    args = parser.parse_args()

    print("Loading context from {}".format(args.context_dir))
    uc = unicorn_loader.AflUnicornEngine(args.context_dir, enable_trace=args.debug, debug_print=False)       

    if args.json_data_file:
        json_file  = open(args.json_data_file, "r")
        data = json.loads(json_file.read())
        harness_data = {key.encode('utf-8'): value for key, value in data.items()}
        print("Loading context from {}".format(args.context_dir))
        
    def unicorn_hook_instruction(uc, address, size, user_data):
        print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size)) 

        if address in harness_data['avoid_addresses']:
                uc.reg_write(UC_MIPS_REG_PC, address+size)

    # Instantiate the hook function to avoid emulation errors
    global unicorn_heap
    unicorn_heap = unicorn_loader.UnicornSimpleHeap(uc, debug_print=True)
    uc.hook_add(UC_HOOK_CODE, unicorn_hook_instruction)

    # Execute 1 instruction just to startup the forkserver
    # NOTE: This instruction will be executed again later, so be sure that
    #       there are no negative consequences to the overall execution state.
    #       If there are, change the later call to emu_start to no re-execute 
    #       the first instruction.
    print("Starting the forkserver by executing 1 instruction")
    try:
        uc.emu_start(harness_data['start'], 0, 0, count=1)
    except UcError as e:
        print("ERROR: Failed to execute a single instruction (error: {})!".format(e))
        return

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
        
        
        # Allocate a new buffer and put the input into it
        buf_addr = unicorn_heap.malloc(len(input_data))
        uc.mem_write(buf_addr, input_data)
        print("Allocated mutated input buffer @ 0x{0:08x}".format(buf_addr))

        # TODO: Set the input into the state so it will be handled
        uc.reg_write(UC_MIPS_REG_S3, buf_addr)
        uc.reg_write(UC_MIPS_REG_V0, len(input_data))
        
    # Run the test
    print("Executing from 0x{0:08x} to 0x{1:08x}".format(harness_data['start'], harness_data['end']))

    try:
        uc.emu_start(harness_data['start'], harness_data['end'], timeout=0, count=0)
    except UcError as e:
        # If something went wrong during emulation a signal is raised to force this 
        # script to crash in a way that AFL can detect ('uc.force_crash()' should be
        # called for any condition that you want AFL to treat as a crash).
        print("Execution failed with error: {}".format(e))
        uc.dump_regs() 
        uc.force_crash(e)

    print("Final register state:")    
    uc.dump_regs()

    print("Done.")    
        
if __name__ == "__main__":
    main()
