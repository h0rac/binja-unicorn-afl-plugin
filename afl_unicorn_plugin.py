#
# (C) Copyright h0rac, 2019
#

import sys

import binaryninja as binja
from binaryninja.binaryview import BinaryViewType
from binaryninja import _binaryninjacore as core
import binaryninja.interaction as interaction
from binaryninja.plugin import PluginCommand, BackgroundTaskThread
from binaryninja.interaction import show_plain_text_report, show_message_box, get_form_input, SeparatorField, OpenFileNameField, get_open_filename_input, get_save_filename_input, DirectoryNameField
from binaryninja.highlight import HighlightColor
from binaryninja.enums import HighlightStandardColor, MessageBoxButtonSet, MessageBoxIcon
import json
import subprocess
import os
import signal

process = None

class AflUnicornRunner(BackgroundTaskThread):

    def __init__(self, view):
        BackgroundTaskThread.__init__(self, "Vulnerability research with afl-unicorn fuzzer started...", True)
        self.view = view
        self.afl_binary = None
        self.dumped_memory = None
        self.inputs = None
        self.outputs = None
        self.harness_file = None
        self.runner = None
        self.proc = None

    def run(self):
        binja.log_info("Starting afl-unicorn fuzzing")
        separator = SeparatorField()
        afl_binary = OpenFileNameField('Select afl-fuzz')
        dumped_memory = DirectoryNameField('Select folder with dumped memory')
        inputs = DirectoryNameField('Select inputs folder')
        outputs = DirectoryNameField('Select outputs folder')
        harness_file = OpenFileNameField('Select harness test file')
        get_form_input([separator, afl_binary, dumped_memory, inputs, outputs, harness_file], "Afl-unicorn Fuzzing Menu")
        binja.log_info("Selected afl-fuzz binary: {0}".format(afl_binary.result))
        binja.log_info("Selected dumped memory folder: {0}".format(dumped_memory.result))
        binja.log_info("Selected inputs folder: {0}".format(inputs.result))
        binja.log_info("Selected outputs folder: {0}".format(outputs.result))
        binja.log_info("Selected harness test file: {0}".format(harness_file.result))

        try:
            if(len(afl_binary.result) <=0 or len(dumped_memory.result) <= 0 or len(inputs.result) <= 0 or len(outputs.result) <= 0 or len(harness_file.result) <=0):
                show_message_box("Afl-Unicorn", "All fields are required !",
                                                MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)
                return
            self.afl_binary = afl_binary.result
            self.dumped_memory = dumped_memory.result
            self.inputs = inputs.result
            self.outputs = outputs.result
            self.harness_file = harness_file.result

            global process
            process = subprocess.Popen([self.afl_binary, '-U' ,'-m' ,'none','-i', self.inputs, '-o', self.outputs, '--', 'python', self.harness_file, self.dumped_memory, '@@'],  preexec_fn=os.setsid)
            binja.log_info('Process {0} started'.format(os.getpgid(process.pid)))
        except TypeError:
            pass
        
    
    @classmethod
    def cancel_task(self, bv):
        binja.log_info("Cancel process {0}".format(os.getpgid(process.pid)))
        os.killpg(os.getpgid(process.pid), signal.SIGTERM) 


    @classmethod
    def fuzz(self, bv):
        # Start a runner thread
        self.runner = AflUnicornRunner(bv)
        self.runner.start()

class AflUnicornUI(PluginCommand):
    """Afl-unicorn UI extenstion class

Attributes:
    start: Starting address in code section
    end:  End address in code section
            avoid_addresses: Addresses that should be skipped during execution of unicorn
"""

    def __init__(self):
        super(AflUnicornUI, self).register_for_address("Set as Start Address",
                                                       "Set unicorn-afl starting point address", self.set_start_address)
        super(AflUnicornUI, self).register_for_address("Set as End Address",
                                                       "Set unicorn-afl end point address", self.set_end_address)
        super(AflUnicornUI, self).register_for_address("Avoid this Address",
                                                       "Avoid unicorn-afl address during emulation", self.avoid_address)
        super(AflUnicornUI, self).register("Clear Avoided Addresses",
                                           "Clear avoided addresses", self.clear_avoided_addresses)
        super(AflUnicornUI, self).register("Save Data for Harness Test",
                                           "Save for afl-unicron tests", self.save_data)
        super(AflUnicornUI, self).register("Load Data from File",
                                           "Load data for afl-unicron tests", self.load_data)
        super(AflUnicornUI, self).register("Start Fuzzing with afl-unicorn",
                                           "Test unicorn execution for afl-unicron", AflUnicornRunner.fuzz)
        super(AflUnicornUI, self).register("Stop Fuzzing with afl-unicorn",
                                           "Stop unicorn execution for afl-unicron", AflUnicornRunner.cancel_task)
        self.start = 0
        self.end = 0
        self.avoid_addresses = []
        self.avoid = 0

    def set_start_address(self, bv, addr):
        if(addr in self.avoid_addresses):
            show_message_box("Afl-Unicorn", "Address is already avoided, can't be used as Start !",
                                            MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)
            return
        try:
            blocks = bv.get_basic_blocks_at(addr)
            for block in blocks:
                if(addr != self.start and self.start != 0):
                    block.function.set_auto_instr_highlight(
                        self.start, HighlightStandardColor.NoHighlightColor)
                    block.function.set_auto_instr_highlight(
                        addr, HighlightStandardColor.OrangeHighlightColor)
                    self.start = addr
                else:
                    block.function.set_auto_instr_highlight(
                        addr, HighlightStandardColor.OrangeHighlightColor)
                    self.start = addr
            binja.log_info("Start: 0x%x" % addr)
        except:
            show_message_box("Afl-Unicorn", "Error please open git issue !",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)

    def set_end_address(self, bv, addr):
        if(addr in self.avoid_addresses):
            show_message_box("Afl-Unicorn", "Address is already avoided, can't be used as End !",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)
            return
        try:
            blocks = bv.get_basic_blocks_at(addr)
            for block in blocks:
                if(addr != self.end and self.end != 0):
                    block.function.set_auto_instr_highlight(
                        self.end, HighlightStandardColor.NoHighlightColor)
                    block.function.set_auto_instr_highlight(
                        addr, HighlightStandardColor.OrangeHighlightColor)
                    self.end = addr
                else:
                    block.function.set_auto_instr_highlight(
                        addr, HighlightStandardColor.OrangeHighlightColor)
                    self.end = addr
            binja.log_info("End: 0x%x" % addr)
        except:
            show_message_box("Afl-Unicorn", "Error please open git issue !",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)

    def avoid_address(self, bv, addr):
        if(addr == self.start or addr == self.end):
            show_message_box("Afl-Unicorn", "Start or End address cannot be avoided !",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.WarningIcon)
            return
        self.avoid = addr
        try:
            blocks = bv.get_basic_blocks_at(addr)
            for block in blocks:
                if(addr == self.avoid and addr in self.avoid_addresses):
                    block.function.set_auto_instr_highlight(
                        self.avoid, HighlightStandardColor.NoHighlightColor)
                    self.avoid_addresses = [
                        x for x in self.avoid_addresses if x != addr]
                    self.avoid = addr
                else:
                    block.function.set_auto_instr_highlight(
                        addr, HighlightStandardColor.RedHighlightColor)
                    if addr not in self.avoid_addresses:
                        self.avoid_addresses.append(addr)
                    self.avoid = addr
            binja.log_info("Avoided Address List: {0}".format(
                [hex(x) for x in self.avoid_addresses]))
        except:
            show_message_box("Afl-Unicorn", "Error please open git issue !",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)

    def clear_avoided_addresses(self, bv):
        if(len(self.avoid_addresses) <= 0):
            show_message_box("Afl-Unicorn", "Cannot clear empty list!",
                                            MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.WarningIcon)
            return
        try:
            for addr in self.avoid_addresses:
                blocks = bv.get_basic_blocks_at(addr)
                for block in blocks:
                    block.function.set_auto_instr_highlight(
                        addr, HighlightStandardColor.NoHighlightColor)
            self.avoid_addresses.clear()
            if(len(self.avoid_addresses) == 0):
                show_message_box("Afl-Unicorn", "All avoided addresses cleared",
                                                MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.InformationIcon)
        except:
            show_message_box("Afl-Unicorn", "Error please open git issue !",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)

    def save_data(self, bv):
        if(self.start == self.end or self.start == 0 or self.end == 0):
            show_message_box("Afl-Unicorn", "Start and End addresses not set!",
                                            MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)
            return
        try:
            data = json.dumps({'start': self.start, 'end': self.end,
                               'avoid_addresses': self.avoid_addresses}, ensure_ascii=False)
            prompt_file = get_save_filename_input('filename', 'json')
            if(not prompt_file):
                show_message_box("Afl-Unicorn", "Filename is not set",
                                                MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.WarningIcon)
                return
            output_file = open(prompt_file.decode("utf-8")+'.json', 'w')
            output_file.write(data)
            output_file.close()
            show_message_box("Afl-Unicorn", "Data saved you can start harness test",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.InformationIcon)
        except:
            show_message_box("Afl-Unicorn", "Error please open git issue !",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)

    def clear_address(self, block, addr):
        for x in block:
            x.function.set_auto_instr_highlight(
                addr, HighlightStandardColor.NoHighlightColor)

    def clear_data(self, bv):
        try:
            start_block = bv.get_basic_blocks_at(self.start)
            end_block = bv.get_basic_blocks_at(self.end)
            self.clear_address(start_block, self.start)
            self.clear_address(end_block, self.end)
            for addr in self.avoid_addresses:
                blocks = bv.get_basic_blocks_at(addr)
                for block in blocks:
                    block.function.set_auto_instr_highlight(
                        addr, HighlightStandardColor.NoHighlightColor)
            self.start = 0x0
            self.end = 0x0
            self.avoid = 0x0
            self.avoid_addresses.clear()
        except:
            show_message_box("Afl-Unicorn", "Error please open git issue !",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)

    def load_data(self, bv):
        prompt_file = get_open_filename_input("filename")
        if(not prompt_file):
            show_message_box("Afl-Unicorn", "You didn't select any file",
                                            MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.WarningIcon)
            return
        input_file = open(prompt_file)
        try:
            harness_data = json.loads(input_file.read())
        except json.decoder.JSONDecodeError:
            show_message_box("Afl-Unicorn", "Invalid json file",
                                            MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)
            return
        self.clear_data(bv)
        binja.log_info("JSON data: start: 0x{0:08x}, end: 0x{1:08x}, avoided addresses: {2}".format(
            harness_data['start'], harness_data['end'], [hex(x) for x in harness_data['avoid_addresses']]))
        self.start = harness_data['start']
        self.end = harness_data['end']
        self.set_start_address(bv, self.start)
        self.set_end_address(bv, self.end)
        for addr in harness_data['avoid_addresses']:
            self.avoid_address(bv, addr)
        input_file.close()
    
    def test_unicorn_setup(self, bv):
        #TO DO add UI menu
        output = subprocess.Popen(['python', '/home/horac/Research/afl-unicorn/unicorn_mode/tplink/tdpd/tdpd_test_harness.py', '-d', '/home/horac/Research/afl-unicorn/unicorn_mode/tplink/tdpd/UnicornContext_20190303_132130', '/home/horac/Research/afl-unicorn/unicorn_mode/tplink/tdpd/inputs/sample1.bin'], stdout = subprocess.PIPE).communicate()[0]
        binja.log_info(output)
        


if __name__ == "__main__":
    pass
else:
    afl_ui = AflUnicornUI()
