import struct, os
from pwnlib.context import *
from pwnlib.asm import *
import re

# section flag and segment flags are different
SH_WRITE = 1
SH_EXEC = 4

PF_R = 4
PF_W = 2
PF_X = 1

class FileStreamString(object):
    def __init__(self, file_name):
        self.file_name = file_name
        self.stream = open(file_name, "rb")
        self.write_stream = None

    def __getitem__(self, idx):
        stream = self.stream if self.write_stream == None else self.write_stream
        stream.seek(idx)
        return stream.read(1)

    def __setitem__(self, idx, data):
        if self.write_stream == None:
            self.write_stream = open(self.file_name + ".change", "w+b")
            self.stream.seek(0)
            self.write_stream.write(self.stream.read())

        self.write_stream.seek(idx)
        self.write_stream.write(data)

    def __getslice__(self, i, j):
        stream = self.stream if self.write_stream == None else self.write_stream
        stream.seek(i)
        return stream.read(j - i)

    def __setslice__(self, i, j, data):
        if self.write_stream == None:
            self.write_stream = open(self.file_name + ".change", "w+b")
            self.stream.seek(0)
            self.write_stream.write(self.stream.read())

        self.write_stream.seek(i)
        self.write_stream.write(data)

    def __del__(self):
        self.stream.close()
        if self.write_stream:
            self.write_stream.close()
            os.unlink(self.file_name + ".change")

    def write_at(self, idx, data):
        if self.write_stream == None:
            self.write_stream = open(self.file_name + ".change", "w+b")
            self.stream.seek(0)
            self.write_stream.write(self.stream.read())

        self.write_stream.seek(idx)
        self.write_stream.write(data)

    def save(self, name):
        stream = self.stream if self.write_stream == None else self.write_stream
        stream.seek(0)

        f = open(name, "wb")
        f.write(stream.read())
        f.close()

class Section(object): #name, stype, flags, address, offset, size
    def __init__(self):
        self.name = 0
        self.stype = 0x0
        self.flags = 0
        self.address = 0
        self.offset = 0
        self.size = 0
        self.str_name = None

    def __repr__(self):
        return "Section<%s>"%(self.str_name)

    def __getitem__(self, name):
        return self.__dict__[name]

    def __hash__(self):
        return hash(self.__repr__)

    def get_permission(self):
        W = SH_WRITE & self.flags
        X = SH_EXEC  & self.flags
        return 'R|%s|%s' % ('W' if W else '-', 'X' if X else '-')

    def set_permission(self, permission):
        if any(map(lambda x: not x in ['R', 'W', 'X'], permission.upper())):
            raise Exception("ILLEGAL Permission: %s" % permission)
        perm = 0
        if 'W' in permission.upper():
            perm |= SH_WRITE
        if 'X' in permission.upper():
            perm |= SH_EXEC
        self.flags = perm

class Segment(object): #p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align
    def __init__(self):
        self.p_type, self.p_offset, self.p_vaddr, self.p_paddr, self.p_filesz, self.p_memsz, self.p_flags, self.p_align = 0,0,0,0,0,0,0,0

    def __repr__(self):
        return "Segment[%x]"%(self.p_paddr)

    def __getitem__(self, name):
        return self.__dict__[name]

    def __hash__(self):
        return hash(self.__repr__)

    def get_permission(self):
        R = PF_R & self.p_flags
        W = PF_W & self.p_flags
        X = PF_X & self.p_flags
        return '%s|%s|%s' % ('R' if R else '-', 'W' if W else '-', 'X' if X else '-')

    def set_permission(self, permission):
        if any(map(lambda x: not x in ['R', 'W', 'X'], permission.upper())):
            raise Exception("ILLEGAL Permission: %s" % permission)
        perm = 0
        if 'R' in permission.upper():
            perm |= PF_R
        if 'W' in permission.upper():
            perm |= PF_W
        if 'X' in permission.upper():
            perm |= PF_X
        self.p_flags = perm

class ELFHeader(object): # ei_mag, ei_class, ei_data, ei_version, ei_osabi,  ei_pad, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
    def __init__(self, data = None, segment = None, section = None):
        if data is None:
            self.ei_mag, self.ei_class, self.ei_data, self.ei_version, self.ei_osabi, self.ei_pad, self.e_type, self.e_machine, self.e_version, self.e_entry, self.e_phoff, self.e_shoff, self.e_flags, self.e_ehsize, self.e_phentsize, self.e_phnum, self.e_shentsize, self.e_shnum, self.e_shstrndx  = 0x464c457F, 1, 1, 1, 3, 0,2, 3, 1, section[0].offset, 52, 52 + len(segment) * 0x20, 0, 52, 0x20, len(segment), 0x28, len(section),len(section)
        else:
            ei_class =  struct.unpack("<B",data[4])[0]
            if ei_class == 1:
                self.ei_mag, self.ei_class, self.ei_data, self.ei_version, self.ei_osabi, self.ei_pad, self.e_type, self.e_machine, self.e_version, self.e_entry, self.e_phoff, self.e_shoff, self.e_flags, self.e_ehsize, self.e_phentsize, self.e_phnum, self.e_shentsize, self.e_shnum, self.e_shstrndx  = struct.unpack("<IBBBBQHHIIIIIHHHHHH",data[:0x34])
            elif ei_class == 2:
                self.ei_mag, self.ei_class, self.ei_data, self.ei_version, self.ei_osabi, self.ei_pad, self.e_type, self.e_machine, self.e_version, self.e_entry, self.e_phoff, self.e_shoff, self.e_flags, self.e_ehsize, self.e_phentsize, self.e_phnum, self.e_shentsize, self.e_shnum, self.e_shstrndx  = struct.unpack("<IBBBBQHHIQQQIHHHHHH",data[:0x40])
    def __getitem__(self, name):
        return self.__dict__[name]

    def __hash__(self):
        return hash(self.__repr__)

class ELFFile(object): # [segment, section]
    def __init__(self, filename):
        self.filename = filename
        self.binData = FileStreamString(filename)

        self._extract_elfHeader()
        self._extract_segment()
        self._extract_section()
        self._resolve_string_table()
        self._set_section_name()
        self._base = min(filter(bool, (s.p_vaddr for s in self.segments)))

    def __repr__(self):
        return "ELFFile<%s>" % (self.filename)

    def __getitem__(self, name):
        return self.__dict__[name]

    def __hash__(self):
        return hash(self.__repr__)

    def _resolve_string_table(self):
        string_table_section_num = self.header['e_shstrndx']
        self.string_table_section = self.sections[string_table_section_num]

    def section_name(self, offset):
        def read_string(string, idx):
            rtn = ''
            while True:
                cur = string[idx]
                if cur == '\x00':
                    return rtn
                else:
                    rtn = rtn + cur
                    idx = idx + 1
            return None

        off = self.string_table_section['offset'] + offset
        return read_string(self.binData, off)

    def _set_section_name(self):
        for section in self.sections:
            section.str_name = self.section_name(section.name)

    def _extract_elfHeader(self):
        self.header = ELFHeader(self.binData)

    def _extract_segment(self):
        self.segments = []
        for i in xrange(self.header.e_phnum):
            segment = Segment()
            if self.header.ei_class == 1:
                segment.p_type, segment.p_offset, segment.p_vaddr, segment.p_paddr, segment.p_filesz, segment.p_memsz, segment.p_flags, segment.p_align = struct.unpack("<IIIIIIII",self.binData[self.header.e_phoff+i*self.header.e_phentsize:self.header.e_phoff+i*self.header.e_phentsize+0x20])
            elif self.header.ei_class == 2:
                segment.p_type, segment.p_offset, segment.p_vaddr, segment.p_paddr, segment.p_filesz, segment.p_memsz, segment.p_flags, segment.p_align = struct.unpack("<IIQQQQQQ",self.binData[self.header.e_phoff+i*self.header.e_phentsize:self.header.e_phoff+i*self.header.e_phentsize+0x38])
            self.segments.append(segment)

    def _extract_section(self):
        self.sections = []
        for i in xrange(self.header.e_shnum):
            section = Section()
            if self.header.ei_class == 1:
                section.name, section.stype, section.flags, section.address, section.offset, section.size = struct.unpack("<IIIIII", self.binData[self.header.e_shoff+i*self.header.e_shentsize : self.header.e_shoff + i*self.header.e_shentsize + 0x18])
            elif self.header.ei_class == 2:
                section.name, section.stype, section.flags, section.address, section.offset, section.size = struct.unpack("<IIQQQQ", self.binData[self.header.e_shoff+i*self.header.e_shentsize : self.header.e_shoff + i*self.header.e_shentsize + 0x28])
            self.sections.append(section)

    def _commit(self): # change binData with no elfHeader change(only section and segment can be changed)
        for i in xrange(self.header.e_phnum):
            a = self.segments[i]
            if self.header.ei_class == 1:
                repData = struct.pack("<IIIIIIII",a.p_type, a.p_offset, a.p_vaddr, a.p_paddr, a.p_filesz, a.p_memsz, a.p_flags, a.p_align)
            elif self.header.ei_class == 2:
                repData = struct.pack("<IIQQQQQQ",a.p_type, a.p_offset, a.p_vaddr, a.p_paddr, a.p_filesz, a.p_memsz, a.p_flags, a.p_align)
            self.write_at(offset = self.header['e_phoff'] + i * self.header['e_phentsize'], data = repData)

        for i in xrange(self.header.e_shnum):
            b = self.sections[i]
            if self.header.ei_class == 1:
                repData = struct.pack("<IIIIII", b.name, b.stype, b.flags, b.address, b.offset, b.size)
            elif self.header.ei_class == 2:
                repData = struct.pack("<IIQQQQ", b.name, b.stype, b.flags, b.address, b.offset, b.size)
            self.write_at(offset = self.header['e_shoff'] + i * self.header['e_shentsize'], data = repData)
        return True

    def write_at(self, **kw):
        _offset = None
        if 'vaddr' in kw.keys():
	    vaddr = kw.get('vaddr')
	    for scs in self.sections:
		if vaddr >= scs.address and vaddr < scs.address + scs.size:
                    _offset = kw.get('vaddr') - scs.address + scs.offset
		    if 'data' in kw.keys() and kw.get('vaddr') + len(kw.get('data')) > scs.address + scs.size:
			print "[*] warning: end of section (increase section size)"
		    break
	    else:
		raise Exception("Can't find memory in section")

            if _offset < 0:
                raise Exception('Illegal vaddr')
            print '[*] Translate vaddr:0x%x to offset:0x%x' %(kw.get('vaddr'), _offset)

        if 'offset' in kw.keys():
            if _offset:
                raise Exception('Cannot use vaddr and offset in kwargs')
            _offset = kw.get('offset')

        if 'data' in kw.keys():
            data = kw.get('data')
        else:
            raise Exception('data required')
        self.binData.write_at(_offset, data)
    
    def write_asm_at(self, **kw):
        if 'vaddr' in kw.keys() and 'data' in kw.keys():
            vaddr1 = kw.get('vaddr')
            context.clear()
            if self.header.ei_class == 1:
                myarch = 'i386'
            elif self.header.ei_class == 2:
                myarch = 'amd64'
            context.arch = myarch
            self.write_at(vaddr = vaddr1, data = make_elf_from_assembly(kw.get('data'), vma = vaddr1, extract = True))
        else:
            raise Exception('vaddr and data required')
    
    def write_codecave_at(self,**kw):
        if self.header.ei_class == 1:
            myarch = 'i386'
        elif self.header.ei_class == 2:
            myarch = 'amd64'
        context.clear()
        context.arch = myarch
        if 'vaddr' in kw.keys() and 'vcave' in kw.keys() and 'data' in kw.keys():
	    vcave1 = kw.get('vcave')
	    vaddr1 = kw.get('vaddr')
	    caved = make_elf_from_assembly('jmp 0x%x' %  vcave1, vma = vaddr1, extract= True)
	    _offset = None
	    for scs in self.sections:
		if vaddr1 >= scs.address and vaddr1 < scs.address + scs.size:
		    _offset = vaddr1 - scs.address + scs.offset
		    break
	    else:
		raise Exception('Can\'t find offset')
	    
	    lencave = len(caved)
	    while '.byte' in disasm(self.binData[_offset:_offset+lencave], arch=myarch):
		lencave += 1
	    vaddr2 = vaddr1 + lencave
	    data1 = make_elf_from_assembly(kw.get('data'), vma = vcave1, extract = True)
	    data2 = self.binData[_offset : _offset + lencave]
	    data3 = make_elf_from_assembly('jmp 0x%x' % vaddr2, vma = vcave1+len(data1) + len(data2) , extract= True)
	    self.write_at(vaddr = vaddr1, data = caved)
	    self.write_at(vaddr = vcave1, data = data1+data2 + data3)


    def write_codecave_auto(self, **kw):
        context.clear()
        if self.header.ei_class == 1:
            context.arch = 'i386'
        elif self.header.ei_class == 2:
            context.arch = 'amd64'
        if 'vaddr' in kw.keys() and 'filename' in kw.keys() and 'data' in kw.keys():
	    ll = [i.split(':') for i in open(kw.get('filename'),'r').read().split('\n')]
	    startv = kw.get('vaddr')
	    pp = []
	    for i in ll:
		if len(i) == 2:
		    pp.append((int(i[1]), int(i[0].replace('L',''),16)))
	    pp.sort()
	    pp = pp[::-1]

	    _offset = None
	    for scs in self.sections:
		if startv >= scs.address and startv < scs.address + scs.size:
		    _offset = startv - scs.address + scs.offset
		    break
	    else:
		raise Exception('Can\'t find offset')
	
	    tmp = pp[0]
	    caved = make_elf_from_assembly('jmp 0x%x' %  tmp[1], vma = startv, extract= True)

	    lencave = len(caved)


	    while '.byte' in disasm(self.binData[_offset:_offset+lencave], arch='i386'):
		lencave += 1

	    endv = startv + lencave 
	    data = re.split(';|\n',kw.get('data'))
	    lastD = disasm(self.binData[_offset:_offset+lencave], offset = 0, byte = 0)
	    for i in lastD.split('\n'):
		data.append(i)
	    #print data

	    self.write_at(vaddr = startv, data = caved)
	    while len(data) != 0:
		curSpace = pp.pop(0)
		curAdd = curSpace[1]
		curSize = curSpace[0]
		curData = ''
		d0 = make_elf_from_assembly(data[0], vma = curAdd, extract = True)
		nextJ = pp[0][1]
		if len(data) == 1:
		    nextJ = endv
		djump = make_elf_from_assembly('jmp 0x%x' % nextJ, vma= curAdd + len(d0), extract = True)
		if len(d0 + djump) > curSize:
		    raise Exception("not enough space, do manual injection")
		curData = d0
		if len(data) == 1:
		    self.write_at(data = d0+djump, vaddr = curAdd)
		    return
		data.pop(0)

		tData = make_elf_from_assembly(data[0], vma = curAdd + len(curData), extract = True)
		nextJ = pp[0][1]
		if len(data) == 1:
		    nextJ = endv
		tJump = make_elf_from_assembly('jmp 0x%x' % nextJ, vma= curAdd + len(curData) + len(tData) , extract = True)
		while len(curData + tData + tJump) <= curSize:
		    curData += tData
		    if len(data) == 1:
			self.write_at(data = curData + tJump, vaddr = curAdd)
			return
		    data.pop(0)
		    tData = make_elf_from_assembly(data[0], vma = curAdd + len(curData), extract = True)
		    nextJ = pp[0][1]
		    if len(data) == 1:
		        nextJ = endv
    		    tJump = make_elf_from_assembly('jmp 0x%x' % nextJ, vma= curAdd + len(curData) + len(tData) , extract = True)
		tJump = make_elf_from_assembly('jmp 0x%x' % pp[0][1], vma= curAdd + len(curData) , extract = True)
		self.write_at(data = curData + tJump, vaddr = curAdd)




    def get_section_by_name(self, name):
        for section in self.sections:
            if section.str_name == name:
                return section
        return None

    def save(self,name):
        self._commit()
        self.binData.save(name)

