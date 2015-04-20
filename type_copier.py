# coding: utf-8
from struct import unpack, pack
import pickle

from idaapi import PLUGIN_OK, PLUGIN_UNL, plugin_t, get_root_filename, BADADDR, get_func, open_pseudocode
from idc import GetFunctionName, GetLocalTypeName, GetMaxLocalType, GetTinfo, NextFunction
from idc import here, ApplyType, LocByName, Jump

"""
Copy unparseable types from one IDB to another.
It requires the unparseable type to be a Local Type in the destination IDB.
The Local Types will have different ordinals in the two IDBs.
"""


class TinfoReader:
	def __init__(self, tp):
		self.pos = 0
		self.tp = tp

	def read_byte(self):
		(result,) = unpack("B", self.tp[self.pos])
		self.pos += 1
		return result

	def keep_going(self):
		return self.pos < len(self.tp)


class CopyTypes(plugin_t):
	flags = PLUGIN_UNL
	comment = "copy types"
	help = "help sir"
	wanted_name = "type_copier.py"
	wanted_hotkey = "{"

	def __init__(self):
		pass

	def receive_message(self, filename):
		msg = None
		try:
			handle = open(filename)
			msg = pickle.loads(handle.read())
			handle.close()
		except IOError:
			pass
		return msg

	def send_message(self, filename, msg):
		handle = open(filename, "w")
		handle.write(pickle.dumps(msg))
		handle.close()

	def find_type_by_name(self, name):
		for i in range(1, GetMaxLocalType()):
			if name == GetLocalTypeName(i):
				return i
		print "didn't find: %s" % name
		raise RuntimeError

	def unparse_tinfo(self, tinfo):
		the_bytes = []
		for thing in tinfo:
			if type(thing) == int:  # if it's a byte, just put it back in
				the_bytes.append(thing)
			else:
				the_bytes.append(ord("="))  # a type starts with =
				ordinal = self.find_type_by_name(thing["local_type"])  # get the ordinal of the Local Type based on its name
				if ordinal < 0x40:
					the_bytes.append(0x3)  # length of "=" + length byte + single byte encoded ordinal
				else:
					the_bytes.append(0x4)  # length of "=" + length byte + two byte encoded ordinal
				the_bytes.append(ord("#"))  # the number symbol means ordinal follows
				if ordinal < 0x40:
					the_bytes.append(ordinal | 0x40)  # encode one byte ordinal
				else:
					the_bytes.append((ordinal >> 6) | 0x80)  # encode two byte ordinal
					the_bytes.append(ordinal & 0x3f | 0x40)
		packed = pack("%dB" % len(the_bytes), *the_bytes)
		return packed

	def parse_tinfo(self, ea):
		tinfo = GetTinfo(ea)
		if tinfo is None:
			return None, None, None
		type_, fields = tinfo

		tp = TinfoReader(type_)
		# print idc_print_type(type_, fields, "fun_name", 0)
		# print type_.encode("string_escape")
		output = []
		"""
		Attempt to copy the tinfo from a location, replacing any Local Types with our own representation of them.
		Pass all other bytes through as-is.
		"""
		while tp.keep_going():
			a_byte = tp.read_byte()
			unwritten_bytes = [a_byte]
			if a_byte == ord("="):  # a type begins
				ordinal_length = tp.read_byte()
				unwritten_bytes.append(ordinal_length)
				if ordinal_length in [0x3, 0x4]:  # if you have more than 0x2000 Local Types you might need to handle the case of 0x5
					number_marker = tp.read_byte()
					unwritten_bytes.append(number_marker)
					if number_marker == ord("#"):  # this is a Local Type referred to by its ordinal
						ordinal = 0
						for w in range(ordinal_length - 2):
							next_byte = tp.read_byte()
							ordinal = ordinal * 0x40 + (next_byte & 0x7f)  # decode ordinal number
						ordinal -= 0x40

						t = GetLocalTypeName(ordinal)
						output.append({"local_type": t})
						continue

			output += unwritten_bytes  # put all the bytes we didn't consume into the output as-is

		return type_, output, fields

	def type_one_function(self, tinfo_map):
		fn_name = GetFunctionName(here())
		if not fn_name:
			print "you're not in a function lol"
			return
		if fn_name not in tinfo_map:
			print "I don't know of this %s" % fn_name
			return
		tinfo, fields = tinfo_map[fn_name]
		fn_loc = LocByName(fn_name)
		current_tinfo_ = GetTinfo(fn_loc)
		packed = self.unparse_tinfo(tinfo)
		if current_tinfo_ is not None:
			current_tinfo, current_fields = current_tinfo_
			if packed == current_tinfo and fields == current_fields:
				print "already the same"
				return
		ret = ApplyType(fn_loc, (packed, fields))
		if ret:
			print "success: %#x %s" % (fn_loc, fn_name)
			open_pseudocode(fn_loc, False)
		else:
			print "failed :("
			print fn_name
			print packed.encode("string_escape")
			print fields.encode("string_escape")

	def dump_tinfos(self, tmp_file):
		tinfo_map = {}
		ea = 0
		num_tinfos = 0
		while True:
			ea = NextFunction(ea)
			if ea == BADADDR:
				break
			fun = get_func(ea)
			fn_name = GetFunctionName(ea)

			tinfo, parsed_tinfo, fields = self.parse_tinfo(fun.startEA)
			if tinfo is None:
				continue
			reconstituted = self.unparse_tinfo(parsed_tinfo)
			if tinfo == reconstituted:
				tinfo_map[fn_name] = (parsed_tinfo, fields)
				num_tinfos += 1
			else:
				print "fuck"
				ea = fun.startEA
				Jump(ea)
				print tinfo.encode("string_escape")
				print reconstituted.encode("string_escape")
				break
		self.send_message(tmp_file, tinfo_map)
		print "dumped %d tinfos" % num_tinfos

	def run(self, arg_=None):
		tmp_file = "/tmp/tinfo_storage"  # windows, do something lol
		if len(get_root_filename()) == 15:  # dest -> 15, source !15
			tinfo_map = self.receive_message(tmp_file)
			self.type_one_function(tinfo_map)
		else:
			self.dump_tinfos(tmp_file)
		print "done"

	def init(self):
		return PLUGIN_OK

	def term(self):
		pass


def PLUGIN_ENTRY():
	return CopyTypes()
