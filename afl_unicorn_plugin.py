#
#(C) Copyright h0rac, 2019
#

import sys

import binaryninja as binja
from binaryninja.binaryview import BinaryViewType
from binaryninja import _binaryninjacore as core
import binaryninja.interaction as interaction
from binaryninja.plugin import PluginCommand
from binaryninja.interaction import show_plain_text_report, show_message_box, get_form_input, OpenFileNameField,get_open_filename_input, get_save_filename_input
from binaryninja.highlight import HighlightColor
from binaryninja.enums import HighlightStandardColor, MessageBoxButtonSet, MessageBoxIcon
import json



class AflUnicornUI(PluginCommand):
	"""Afl-unicorn UI extenstion class

    Attributes:
        start: Starting address in code section
        end:  End address in code section
		avoid_addresses: Addresses that should be skipped during execution of unicorn
    """
	def __init__(self):
		super(AflUnicornUI, self).register_for_address("Set as Start Address:", "Set unicorn-afl starting point address", self.set_start_address)
		super(AflUnicornUI, self).register_for_address("Set as End Address:", "Set unicorn-afl end point address", self.set_end_address)
		super(AflUnicornUI, self).register_for_address("Avoid this Address:", "Avoid unicorn-afl address during emulation", self.avoid_address)
		super(AflUnicornUI, self).register("Clear Avoided Addresses:", "Clear avoided addresses", self.clear_avoided_addresses)
		super(AflUnicornUI, self).register("Save Data for Harness Test:", "Save for afl-unicron tests", self.save_data)
		super(AflUnicornUI, self).register("Load Data from File:", "Load data for afl-unicron tests", self.load_data)
		
		self.start = 0
		self.end = 0
		self.avoid_addresses = []
		self.avoid = 0

	def set_start_address(self,bv, addr):
		if(addr in self.avoid_addresses):
			show_message_box("Afl-Unicorn", "Address is already avoided, can't be used as Start !",
							MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)
			return
		try:		
			blocks = bv.get_basic_blocks_at(addr)
			for block in blocks:
				if(addr != self.start and self.start != 0):
					block.function.set_auto_instr_highlight(self.start, HighlightStandardColor.NoHighlightColor)
					block.function.set_auto_instr_highlight(addr, HighlightStandardColor.OrangeHighlightColor)
					self.start = addr
				else:
					block.function.set_auto_instr_highlight(addr, HighlightStandardColor.OrangeHighlightColor)
					self.start = addr
			binja.log_info("Start: 0x%x" % addr)
		except:
			show_message_box("Afl-Unicorn", "Error please open git issue !",
					MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)


	def set_end_address(self,bv, addr):
		if(addr in self.avoid_addresses):
			show_message_box("Afl-Unicorn", "Address is already avoided, can't be used as End !",
					MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)
			return
		try:
			blocks = bv.get_basic_blocks_at(addr)
			for block in blocks:
				if(addr != self.end and self.end != 0):
					block.function.set_auto_instr_highlight(self.end, HighlightStandardColor.NoHighlightColor)
					block.function.set_auto_instr_highlight(addr, HighlightStandardColor.OrangeHighlightColor)
					self.end = addr
				else:
					block.function.set_auto_instr_highlight(addr, HighlightStandardColor.OrangeHighlightColor)
					self.end = addr
			binja.log_info("End: 0x%x" % addr)
		except:
			show_message_box("Afl-Unicorn", "Error please open git issue !",
					MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)


	def avoid_address(self,bv, addr):
		if(addr == self.start or addr == self.end):
			show_message_box("Afl-Unicorn", "Start or End address cannot be avoided !",
					MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.WarningIcon)
			return
		self.avoid = addr
		try:
			blocks = bv.get_basic_blocks_at(addr)
			for block in blocks:
				if(addr == self.avoid and addr in self.avoid_addresses):
					block.function.set_auto_instr_highlight(self.avoid, HighlightStandardColor.NoHighlightColor)
					self.avoid_addresses = [x for x in self.avoid_addresses if x != addr]
					self.avoid = addr
				else:
					block.function.set_auto_instr_highlight(addr, HighlightStandardColor.RedHighlightColor)
					if addr not in self.avoid_addresses:
						self.avoid_addresses.append(addr)
					self.avoid = addr
			binja.log_info("Avoided Address List: {0}".format([hex(x) for x in self.avoid_addresses]))
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
					block.function.set_auto_instr_highlight(addr, HighlightStandardColor.NoHighlightColor)
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
			data = json.dumps({'start': self.start, 'end': self.end, 'avoid_addresses':self.avoid_addresses}, ensure_ascii=False)
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
			x.function.set_auto_instr_highlight(addr, HighlightStandardColor.NoHighlightColor)
	
	def clear_data(self, bv):
		try:
			start_block = bv.get_basic_blocks_at(self.start)
			end_block = bv.get_basic_blocks_at(self.end)
			self.clear_address(start_block, self.start)
			self.clear_address(end_block, self.end)
			for addr in self.avoid_addresses:
				blocks = bv.get_basic_blocks_at(addr)
				for block in blocks:
					block.function.set_auto_instr_highlight(addr, HighlightStandardColor.NoHighlightColor)
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
		binja.log_info("JSON data: start: 0x{0:08x}, end: 0x{1:08x}, avoided addresses: {2}".format(harness_data['start'], harness_data['end'], [hex(x) for x in harness_data['avoid_addresses']]))
		self.start = harness_data['start']
		self.end = harness_data['end']
		self.set_start_address(bv, self.start)
		self.set_end_address(bv, self.end)
		for addr in harness_data['avoid_addresses']:
			self.avoid_address(bv, addr)
		input_file.close()

if __name__ == "__main__":
	pass
else:
	afl_ui = AflUnicornUI()