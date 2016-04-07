#!/usr/bin/env python

from pyparsing import cppStyleComment,dblQuotedString
import re
import sys

###################
## Careful with the removing of print statements
## This can cause major issues if we delete a print statements and it's the only
## on the line or in the function :-/
###################
def removeCommentsGo(fStr,fName='',removePrint=False):
	
	returnStr = fStr
	raw_lookup_table = ''
	lookup_table=''
	fixStr = ''

	# First remove the large blobs of data so we don't hit memory faults :-/
	raw_lookup_table_query = re.compile(r'    raw_lookup_table.*?\n',re.I)
	lookup_table_query = re.compile(r'    lookup_table.*?\n',re.I)

	try:
		raw_lookup_table = re.search(raw_lookup_table_query,returnStr).group()
	except: raw_lookup_table = ''

	try:
		lookup_table = re.search(lookup_table_query,returnStr).group()
	except: lookup_table = ''

	if raw_lookup_table:
		returnStr = re.sub(raw_lookup_table_query,'    raw_lookup_table := ""\n',returnStr)

	if lookup_table:
		returnStr = re.sub(lookup_table_query,'    lookup_table := ""\n',returnStr)

	#####
	cppStyleComment.ignore(dblQuotedString)
	v1 = cppStyleComment.suppress().transformString(returnStr)

	if removePrint:
		comp2 = re.compile(r'^\s*fmt.P.*?\n',re.MULTILINE)
		v2 = re.sub(comp2,"",v1)
		returnStr = v2
		#Check for the case of fmt.Sprintf or other fmt modifications that are not printing
		if not "fmt." in v2:
			comp3 = re.compile(r'^\s*\"fmt\".*?\n',re.MULTILINE)
			v3 = re.sub(comp3,"",v2)
			returnStr = v3
		#Ugggggh deal with the C import types :(
		if "import \"C\"" in returnStr:
			#print "In Import C Section"
			comp4 = re.compile(r'^import \"C\".*?\n',re.MULTILINE)
			repVal = '''/*
#cgo CFLAGS: -IMemoryModule
#cgo LDFLAGS: MemoryModule/build/MemoryModule.a
#include "MemoryModule/MemoryModule.h"
*/
import "C"
'''
			v4 = re.sub(comp4,repVal,returnStr)
			returnStr = v4
	else:
		returnStr = v1
	
	#### Inject back in the blobs
	returnStr = re.sub(raw_lookup_table_query,raw_lookup_table,returnStr)
	returnStr = re.sub(lookup_table_query,lookup_table,returnStr)
	#######

	if fName:
		try: 
			myOut = open(fileN+'_clean','w')
			myOut.write(returnStr)
			myOut.close()
		except:
			print "[!] Can not write output file"
	else:
		return returnStr


def removeCommentsPy(fStr,fName='',removePrint=False):
	returnStr = ""

	comp1 = re.compile(r'^\s*\'\'\'.*?\n.*?\'\'\'',re.MULTILINE|re.DOTALL)
	v1 = re.sub( comp1,"",fStr)

	comp2 = re.compile(r'^\s*#.*\n',re.MULTILINE)
	v2 = re.sub( comp2,"", v1)

	if removePrint:
		comp3 = re.compile(r'print.*?\n',re.MULTILINE)
		v3 = re.sub(comp3,"blank=None\n",v2)
		returnStr = v3

	else:
		returnStr = v2

	if fName:
		try: 
			myOut = open(fileN+'_clean','w')
			myOut.write(returnStr)
			myOut.close()
		except:
			print "[!] Can not write output file"
	else:
		return returnStr


if __name__ == "__main__":

	if len(sys.argv) != 3:
		print "This tool requires a file name and language type (GO / PY)"
		print "%s big_file.py PY" % sys.argv[0]
		print "%s small_file.go GO" % sys.argv[0]
		exit(-1)

	try:
		myFile = open(sys.argv[1],'r')
		fStr = myFile.read()
		myFile.close()
	except:
		print "Error Opening File to Read: %s" % (sys.argv[1])
		exit(-1)

	if 'go' in sys.argv[2].lower():
		print "[*] Cleaning GO File: %s" % sys.argv[1]
		removeCommentsGo(fStr,sys.argv[1],removePrint=True)
	else:
		removeCommentsPy(fStr, sys.argv[1],removePrint=True)
		print "[*] Cleaning PY File: %s" % sys.argv[1]
