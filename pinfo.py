#!/usr/bin/env python
# (c) 2016 Silas Cutler <silas.cutler@BlackListThisDomain.com>
# Outputs File hashes + Section details


import sys
import pefile
import hashlib

PACKERS = {
        'aspack': 'Aspack packer',
        'adata': 'Aspack packer/Armadillo packer',
        'ASPack': 'Aspack packer',
        'ASPack': 'ASPAck Protector',
        'ccg': 'CCG Packer (Chinese Packer)',
        'charmve': 'Added by the PIN tool',
        'BitArts': 'Crunch 2.0 Packer',
        'DAStub': 'DAStub Dragon Armor protector',
        '!EPack': 'Epack packer',
        'FSG!': 'FSG packer (not a section name, but a good identifier)',
        'kkrunchy': 'kkrunchy Packer',
        'mackt': 'ImpRec-created section',
        'MaskPE': 'MaskPE Packer',
        'MEW': 'MEW packer',
        'MPRESS1': 'Mpress Packer',
        'MPRESS2': 'Mpress Packer',
        'neolite': 'Neolite Packer',
        'neolit': 'Neolite Packer', 
        'nsp1': 'NsPack packer',
        'nsp0': 'NsPack packer',
        'nsp2': 'NsPack packer',
        'nsp1': 'NsPack packer',
        'nsp0': 'NsPack packer',
        'nsp2': 'NsPack packer',
        'packed': 'RLPack Packer (first section)',
        'pebundle': 'PEBundle Packer',
        'PEBundle': 'PEBundle Packer',
        'PEC2TO': 'PECompact packer',
        'PECompact2': 'PECompact packer (not a section name, but a good identifier)',
        'PEC2': 'PECompact packer',
        'pec1': 'PECompact packer',
        'pec2': 'PECompact packer',
        'PEC2MO': 'PECompact packer',
        'PELOCKnt': 'PELock Protector',
        'perplex': 'Perplex PE-Protector',
        'PESHiELD': 'PEShield Packer',
        'petite': 'Petite Packer',
        'pinclie': 'Added by the PIN tool',
        'ProCrypt': 'ProCrypt Packer',
        'RLPack': 'RLPack Packer (second section)',
        'rmnet': 'Ramnit virus marker',
        'RCryptor': 'RPCrypt Packer',
        'RPCrypt': 'RPCrypt Packer',
        'sforce3': 'StarForce Protection',
        'spack': 'Simple Pack (by bagie)',
        'svkp': 'SVKP packer',
        'Themida': 'Themida Packer',
        'Themida': 'Themida Packer',
        'tsuarch': 'TSULoader',
        'tsustub': 'TSULoader', 
        'packed': 'Unknown Packer',
        'PEPACK!!': 'Pepack',
        'Upack': 'Upack packer',
        'ByDwing': 'Upack Packer',
        'UPX0': 'UPX packer',
        'UPX1': 'UPX packer',
        'UPX2': 'UPX packer',
        'UPX!': 'UPX packer',
        'UPX0': 'UPX Packer',
        'UPX1': 'UPX Packer',
        'UPX2': 'UPX Packer',
        'vmp0': 'VMProtect packer',
        'vmp1': 'VMProtect packer',
        'vmp2': 'VMProtect packer',
        'VProtect': 'Vprotect Packer',
        'winapi': 'Added by API Override tool',
        'WinLicen': 'WinLicense (Themida) Protector',
        'WWPACK': 'WWPACK Packer',
        'yP': 'Y0da Protector',
        'y0da': 'Y0da Protector'
}

COMMON_NAMES = {
        'arch': 'Alpha-architecture section',
        'bindat': 'Binary data (also used by one of the downware installers based on LUA)',
        'bss': 'Uninitialized Data Section',
        'BSS': 'Uninitialized Data Section',
        'code': 'Code Section',
        'cormeta': 'CLR Metadata Section',
        'complua': 'Binary data, most likely compiled LUA (also used by one of the downware installers based on LUA)',
        'CRT': 'Initialized Data Section  (C RunTime)',
        'data': 'Data Section',
        'DATA': 'Data Section',
        'data1': 'Data Section',
        'data2': 'Data Section',
        'data3': 'Data Section',   
        'debug': 'Debug info Section',
        'debug$F': 'Debug info Section (Visual C++ version <7.0)',
        'debug$P': 'Debug info Section (Visual C++ debug information - precompiled information',
        'debug$S': 'Debug info Section (Visual C++ debug information - symbolic information)',
        'debug$T': 'Debug info Section (Visual C++ debug information - type information)',
        'drectve ': 'directive section (temporary, linker removes it after processing it; should not appear in a final PE image)',
        'didat': 'Delay Import Section',
        'didata': 'Delay Import Section',
        'edata': 'Export Data Section',
        'export': 'Alternative Export Data Section',
        'fasm': 'FASM flat Section',
        'flat': 'FASM flat Section',
        'idata': 'Initialized Data Section  (Borland)',
        'idlsym': 'IDL Attributes (registered SEH)',
        'impdata': 'Alternative Import data section',
        'itext': 'Code Section  (Borland)',
        'ndata': 'Nullsoft Installer section',
        'orpc': 'Code section inside rpcrt4.dll',
        'pdata': 'Exception Handling Functions Section (PDATA records)',
        'rdata': 'Read-only initialized Data Section  (MS and Borland)',
        'reloc': 'Relocations Section', 
        'rodata': 'Read-only Data Section',
        'rsrc': 'Resource section',
        'sbss': 'GP-relative Uninitialized Data Section',
        'script': 'Section containing script',
        'shared': 'Shared section',
        'sdata': 'GP-relative Initialized Data Section',
        'srdata': 'GP-relative Read-only Data Section',
        'stab': 'Created by Haskell compiler (GHC)',
        'stabstr': 'Created by Haskell compiler (GHC)',
        'sxdata': 'Registered Exception Handlers Section',
        'text': 'Code Section',
        'text0': 'Alternative Code Section',
        'text1': 'Alternative Code Section',
        'text2': 'Alternative Code Section',
        'textbss': 'Section used by incremental linking',
        'tls': 'Thread Local Storage Section',
        'tls$': 'Thread Local Storage Section',
        'udata': 'Uninitialized Data Section',
        'vsdata': 'GP-relative Initialized Data',
        'xdata': 'Exception Information Section',
        'BSS': 'Uninitialized Data Section  (Borland)',
        'CODE': 'Code Section (Borland)',
        'DATA': 'Data Section (Borland)',
        'DGROUP': 'Legacy data group section',
        'edata': 'Export Data Section',
        'idata': 'Initialized Data Section  (C RunTime)',
        'INIT': 'INIT section (drivers)',
        'PAGE': 'PAGE section (drivers)',
        'rdata': 'Read-only Data Section',
        'sdata': 'Initialized Data Section',
        'shared': 'Shared section',
        'Shared': 'Shared section',
        'text': 'Alternative Code Section'
}




# Based on https://github.com/erocarrera/pefile/blob/master/pefile.py:594
def lookup_packer( name ):
        results = []
        if name.startswith('.'): name = name[1:]
        for key in PACKERS.keys():
                if name.lower() == key.lower():
                        results.append( PACKERS[key] )
        return results



def lookup_common( name ):
	results = []
	if name.startswith('.'): name = name[1:]
	for key in COMMON_NAMES.keys():
		if name.lower() == key.lower():
			results.append( COMMON_NAMES[key] )
	return results



def print_hashes(rdata):
	print "MD5:    {}".format(str(hashlib.md5(rdata).hexdigest()) )
	print "SHA1:   {}".format(str(hashlib.sha1(rdata).hexdigest()) )
	print "SHA256: {}".format(str(hashlib.sha256(rdata).hexdigest()) )

def readfile():
	try:
	        fhandle = open( sys.argv[1], 'rb')
	        fdata = fhandle.read()
	        fhandle.close()
		return fdata
	except Exception, e:
		print " [e] Error: %s" % e
		return False
def parse_pe_header(rdata):
	try:
		pe = pefile.PE(data=rdata)
		
	except Exception,e :
		print e
		return False
	print "\nPE Sections:"
	print " {:^7} {:^8} {:^8} {:^8} {:^8} | Notes: \n".format("[ Name ]", "vaddr", "MSize", "size", "raddr" )
	for section in pe.sections:
		name = str(section.Name.replace("\x00", '') )
		print " {:^8} {:^8} {:^8} {:^8} {:^8} ".format("[" + name + "]", hex(section.VirtualAddress),hex(section.Misc_VirtualSize), section.SizeOfRawData, hex(section.PointerToRawData) ),

		pkrs = lookup_packer(name)
		if len(pkrs) > 0:
			print "{}".format(",".join(pkrs) ), 

                cmn_names = lookup_common(name)
		if len(cmn_names) > 0:
	                print "{}".format(",".join(cmn_names) ), 
		print ""

	 

def main():
	if len(sys.argv) != 2:
		print "Usage!"
		return False

	rdata = readfile()
	if not rdata:
		return False

	print_hashes(rdata)

	parsed_pe = parse_pe_header(rdata)
	






if __name__ == "__main__":
	main()

