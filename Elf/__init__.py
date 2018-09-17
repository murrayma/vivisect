"""
Kenshoto's Elf parser

This package will let you use programatic ninja-fu
when trying to parse Elf binaries.  The API is based
around several objects representing constructs in the
Elf binary format.  The Elf object itself contains
parsed metadata and lists of things like section headers
and relocation entries.  Additionally, most of the
objects implement repr() in some form or another which
allows you a bunch of readelf-like functionality.

*Eventually* this API will allow you to modify Elf binaries
and spit them back out in working order (not complete, you
may notice some of the initial code).

Send bug reports to Invisigoth or Metr0.

"""
# Copyright (C) 2007 Invisigoth - See LICENSE file for details
import os
import sys
import struct
import traceback
import zlib

from stat import *
from Elf.elf_lookup import *
import vstruct
import vstruct.defs.elf as vs_elf

verbose = False
HACK_SYMTABSZ = -1   # ELF doesn't have a SYMTABSZ entry, we're creating our own


class ElfReloc:
    """
    Elf relocation entries consist mostly of "fixup" address which
    are taken care of by the loader at runtime.  Things like
    GOT entries, PLT jmp codes etc all have an Elf relocation
    entry.
    """

    def __init__(self):
        self.name = ""

    def __repr__(self):
        return "reloc: @%s %d %s" % (hex(self.r_offset),self.getType(),self.getName())

    def setName(self, name):
        self.name = name

    def getName(self):
        return self.name

    def getType(self):
        return self.r_info & 0xff

class Elf32Reloc(ElfReloc, vs_elf.Elf32Reloc):
    def __init__(self, bigend=False):
        vs_elf.Elf32Reloc.__init__(self, bigend=bigend)
        ElfReloc.__init__(self)

    def getSymTabIndex(self):
        return self.r_info >> 8

class Elf32Reloca(ElfReloc, vs_elf.Elf32Reloca):
    def __init__(self, bigend=False):
        vs_elf.Elf32Reloca.__init__(self, bigend=bigend)
        ElfReloc.__init__(self)

    def getSymTabIndex(self):
        return self.r_info >> 8

class Elf64Reloc(ElfReloc, vs_elf.Elf64Reloc):
    def __init__(self, bigend=False):
        vs_elf.Elf64Reloc.__init__(self, bigend=bigend)
        ElfReloc.__init__(self)

    def getSymTabIndex(self):
        return self.r_info >> 32

class Elf64Reloca(ElfReloc, vs_elf.Elf64Reloca):
    def __init__(self, bigend=False):
        vs_elf.Elf64Reloca.__init__(self, bigend=bigend)
        ElfReloc.__init__(self)

    def getSymTabIndex(self):
        return self.r_info >> 32

class ElfDynamic:
    has_string = [DT_NEEDED,DT_SONAME]
    """
    An object to represent an Elf dynamic entry.
    (linker/loader directives)
    """

    def __init__(self, bytes=None):
        self.name = ""

    def __repr__(self):
        name = self.getName()
        if not name:
            name = hex(self.d_value)
        return "%s %s" % (name,self.getTypeName())

    def getName(self):
        return self.name

    def setName(self, name):
        self.name = name

    def getTypeName(self):
        return dt_types.get(self.d_tag,"Unknown: %s"%hex(self.d_tag))

class Elf32Dynamic(ElfDynamic, vs_elf.Elf32Dynamic):
    def __init__(self, bigend=False):
        vs_elf.Elf32Dynamic.__init__(self, bigend=bigend)
        ElfDynamic.__init__(self)

class Elf64Dynamic(ElfDynamic, vs_elf.Elf64Dynamic):
    def __init__(self, bigend=False):
        vs_elf.Elf64Dynamic.__init__(self, bigend=bigend)
        ElfDynamic.__init__(self)

class ElfSymbol:
    def __init__(self):
        self.name = ""

    def getInfoType(self):
        return self.st_info & 0xf

    def getInfoBind(self):
        return self.st_info >> 4

    def __cmp__(self, other):
        if self.st_value > other.st_value:
            return 1
        return -1

    def setName(self,name):
        self.name = name

    def getName(self):
        return self.name

    def __repr__(self):
        return "0x%.8x %d %s" % (self.st_value, self.st_size, self.name)

class Elf32Symbol(ElfSymbol, vs_elf.Elf32Symbol):
    def __init__(self, bigend=False):
        vs_elf.Elf32Symbol.__init__(self, bigend=bigend)
        ElfSymbol.__init__(self)

class Elf64Symbol(ElfSymbol, vs_elf.Elf64Symbol):
    def __init__(self, bigend=False):
        vs_elf.Elf64Symbol.__init__(self, bigend=bigend)
        ElfSymbol.__init__(self)

class ElfPheader:

    def __init__(self):
        pass

    def getTypeName(self):
        return ph_types.get(self.p_type, "Unknown")

    def __repr__(self):
        return '[%35s] VMA: 0x%.8x  offset: %8d  memsize: %8d  align: %8d  (filesz: %8d)  flags: %x' % (
            self.getTypeName(),
            self.p_vaddr,
            self.p_offset,
            self.p_memsz,
            self.p_align,
            self.p_filesz,
            self.p_flags)

class Elf32Pheader(ElfPheader, vs_elf.Elf32Pheader):
    def __init__(self, bigend=False):
        vs_elf.Elf32Pheader.__init__(self, bigend=bigend)
        ElfPheader.__init__(self)

class Elf64Pheader(ElfPheader, vs_elf.Elf64Pheader):
    def __init__(self, bigend=False):
        vs_elf.Elf64Pheader.__init__(self, bigend=bigend)
        ElfPheader.__init__(self)

class ElfSection:
    def __init__(self):
        self.name = ''

    def setName(self, name):
        self.name = name

    def getName(self):
        return self.name

    def __repr__(self):
        return 'Elf Sec: [%20s] @0x%.8x (%8d)  ent/size: %8d/%8d  align: %8d' % (
                self.name,
                self.sh_addr,
                self.sh_offset,
                self.sh_entsize,
                self.sh_size,
                self.sh_addralign)
    
class Elf32Section(ElfSection, vs_elf.Elf32Section):
    def __init__(self, bigend=False):
        vs_elf.Elf32Section.__init__(self, bigend=bigend)
        ElfSection.__init__(self)

class Elf64Section(ElfSection, vs_elf.Elf64Section):
    def __init__(self, bigend=False):
        vs_elf.Elf64Section.__init__(self, bigend=bigend)
        ElfSection.__init__(self)

class Elf(vs_elf.Elf32, vs_elf.Elf64):

    def __init__(self, fd, inmem=False):

        # Grab a 32bit header to use to check for other
        # machine types...
        e = vs_elf.Elf32()
        fd.seek(0)
        bytes = fd.read(len(e))
        e.vsParse(bytes)
        
        if e.e_data == ELFDATA2MSB:
            bigend = True
        else:
            bigend = False
            
        #Parse 32bit header
        if e.e_class == ELFCLASS32:
            vs_elf.Elf32.__init__(self, bigend=bigend)
            self.bits = 32
            self.psize = 4

            self._cls_reloc  = Elf32Reloc
            self._cls_reloca = Elf32Reloca
            self._cls_symbol = Elf32Symbol
            self._cls_section = Elf32Section
        #Parse 64bit header
        elif e.e_class == ELFCLASS64:
            vs_elf.Elf64.__init__(self, bigend=bigend)
            self.bits = 64
            self.psize = 8

            self._cls_reloc  = Elf64Reloc
            self._cls_reloca = Elf64Reloca
            self._cls_symbol = Elf64Symbol
            self._cls_section = Elf64Section
        else:
            raise Exception('Unrecognized e_class: %d' % e.e_class)

        self.fd = fd
        self.bigend = bigend
        
        bytes = self.readAtOffset(0, len(self))
        self.vsParse(bytes)

        if self.e_machine == EM_386:
            self.r_types = r_types_386
        elif self.e_machine == EM_X86_64:
            self.r_types = r_types_amd64
        else:
            self.r_types = {}

        self.pheaders = []
        self.sections = []
        self.secnames = {}
        self.symbols  = []
        self.relocs   = []
        self.symbols_by_name = {}
        self.symbols_by_addr = {}
        self.dynamics = []
        self.dynamic_symbols = []
        self.strtab = None

        self._parsePheaders()
        self._parseSections()
        self._parseDynLinkInfo()
        self._parseDynSyms()
        self._parseSymbols()
        self._parseDynRelocs()

    def getRelocTypeName(self, rtype):
        '''
        Because relocation type names are decided based on the
        arch, only the Elf knows for sure...
        '''
        return self.r_types.get(rtype)

    def _parsePheaders(self):
        # Load up any program headers we find
        if self.e_phoff:
            pbase = self.e_phoff
            plen = self.e_phentsize
            for i in range(self.e_phnum):
                if self.bits == 32:
                    pgm = Elf32Pheader(bigend=self.bigend)
                elif self.bits == 64:
                    pgm = Elf64Pheader(bigend=self.bigend)
                else:
                    raise Exception('Platform not supported: %d' % (self.bits))

                bytes = self.readAtOffset(pbase, plen)
                pgm.vsParse(bytes)

                self.pheaders.append(pgm)
                pbase += plen

    def _parseSections(self):
        # Load up all the section headers
        if self.e_shoff:
            # Load up the sections
            sbase = self.e_shoff
            sec = self._cls_section(bigend=self.bigend)
            slen = self.e_shentsize
            if len(sec) != slen:
                raise Exception('Invalid Section Header Size: %d' % slen)

            secbytes = self.readAtOffset(sbase, self.e_shnum * slen)

            secs = sec * self.e_shnum
            vstruct.VArray(elems=secs).vsParse(secbytes,fast=True)

            self.sections.extend(secs)

            # Populate the section names
            strsec = self.sections[self.e_shstrndx]
            names = self.readAtOffset(strsec.sh_offset,strsec.sh_size)
            for sec in self.sections:
                name = names[sec.sh_name:].split("\x00")[0]
                if len(name) > 0:
                    sec.setName(name)
                    self.secnames[name] = sec

    def _parseSymbols(self):
        """
        Parse out the symbols that this elf binary has for us.
        """
        for sec in self.sections:
            if sec.sh_type == SHT_SYMTAB:
                sym = self._cls_symbol(bigend=self.bigend)
                symtab = self.readAtOffset(sec.sh_offset, sec.sh_size)

                count,remain = divmod(sec.sh_size,len(sym))
                syms = sym * count

                vstruct.VArray(elems=syms).vsParse(symtab,fast=True)

                for sym in syms:
                    if sym.st_name:
                        name = self.getStrtabString(sym.st_name, ".strtab")
                        sym.setName(name)

                    self.addSymbol(sym)

    def getDynRelInfo(self):
        rel = self.dyns.get(DT_REL)
        relent = self.dyns.get(DT_RELENT)
        relsz = self.dyns.get(DT_RELSZ)
        return rel, relent, relsz

    def getDynRelaInfo(self):
        rela = self.dyns.get(DT_RELA)
        relaent = self.dyns.get(DT_RELAENT)
        relasz = self.dyns.get(DT_RELASZ)
        return rela, relaent, relasz

    def getDynPltRelInfo(self):
        jmprel = self.dyns.get(DT_JMPREL)
        pltrel = self.dyns.get(DT_PLTREL)
        pltrelsz = self.dyns.get(DT_PLTRELSZ)
        return jmprel, pltrel, pltrelsz

    def _parseDynRelocs(self):
        """
        Parse all the relocation entries out of Dyn table entries based at
        * REL
        * RELA
        * JMPREL
        """
        rel, relent, relsz = self.getDynRelInfo()
        if rel != None:
            cls = self._cls_reloc
            self._doRelocs(rel, relsz, cls)

        rela, relaent, relasz = self.getDynRelaInfo()
        if rela != None:
            cls = self._cls_reloca
            self._doRelocs(rela, relasz, cls)

        jmprel, pltrel, pltrelsz = self.getDynPltRelInfo()
        if jmprel != None:
            cls = (self._cls_reloc, self._cls_reloca)[pltrel==DT_RELA]
            self._doRelocs(jmprel, pltrelsz, cls)


    def _doRelocs(self, rva, relsz, cls=None):
        if cls == None:
            cls = self._cls_reloc

        reloc = cls(bigend=self.bigend)
        relbytes = self.readAtRva(rva, relsz)
        #print repr(relbytes)
        count, remain = divmod(relsz, len(reloc))

        relocs = reloc * count
        vstruct.VArray(elems=relocs).vsParse(relbytes,fast=True)

        for reloc in relocs:
            index = reloc.getSymTabIndex()
            if index < len(self.dynamic_symbols):
                sym = self.dynamic_symbols[index]
                reloc.setName( sym.getName() )
            self.relocs.append(reloc)

    def getBaseAddress(self):
        """
        For prelinked and main-exe elf binaries, return the
        value for the loaded base address...
        """
        shrd = self.isSharedObject()
        plnk = self.isPreLinked()

        # If it's a shared object and *not* prelinked,
        # we need to select a base address for it
        # FIXME find non-coliding addr in workspace
        if shrd and not plnk:
            return 0x02000000

        # Find the best base address from the list of
        # section addresses...
        base = None
        for pgm in self.getPheaders():

            if pgm.p_vaddr == 0:
                continue

            if base == None:
                base = pgm.p_vaddr
                continue

            if pgm.p_vaddr < base:
                base = pgm.p_vaddr

        if base == None:
            base = 0x20000000

        base &= 0xfffff000
        return base

    def readAtRva(self, rva, size):
        '''
        Calculate the file offset for the given RVA and
        read from it...
        '''
        return self.readAtOffset(self.rvaToOffset(rva), size)

    def rvaToOffset(self, rva):
        '''
        Convert an RVA for this ELF binary to a file offset.
        '''
        baseaddr = 0
        #if self.isPreLinked() or not self.isSharedObject():
        #if not self.isSharedObject():
            #print 'SUBTRACTING CALCULATED BASE'
            #baseaddr = self.getBaseAddress()

        for pgm in self.pheaders:
            if pgm.p_type != PT_LOAD:
                continue
            phrva = pgm.p_vaddr - baseaddr
            if rva < phrva:
                continue
            if rva >= phrva+pgm.p_memsz:
                continue
            # We are inside this pgrm header!
            rvaoff = rva - phrva
            return pgm.p_offset + rvaoff

        raise 'omg',hex(rva)
        return None

    def readAtOffset(self, off, size):
        '''
        Read from the given file offset.
        '''
        self.fd.seek(off)
        return self.fd.read(size)

    def getSection(self, secname):
        return self.secnames.get(secname,None)

    def getSections(self):
        """
        Return the array of sections for this Elf
        """
        return list(self.sections)

    def getSectionBytes(self, secname):
        sec = self.getSection(secname)
        if sec == None:
            return None
        return self.readAtOffset(sec.sh_offset, sec.sh_size)

    def getStrtabString(self, offset, section=".strtab"):
        sec = self.getSection(section)
        bytes = self.readAtOffset(sec.sh_offset, sec.sh_size)
        index = bytes.find("\x00", offset)
        return bytes[offset:index]

    def getNotes(self):
        '''
        Retrieve a list of the ElfNote vstructs from any
        sections of type SHT_NOTE.

        Example:
            for note in e.getNotes():
                print('%s : %d' % (e.name,e.ntype))
        '''
        for sec in self.getSections():
            if sec.sh_type != SHT_NOTE:
                continue

            notebytes =  self.readAtOffset(sec.sh_offset, sec.sh_size)
            offset = 0
            notebyteslen = len(notebytes)
            while offset < notebyteslen:
                note = vs_elf.ElfNote()
                if notebyteslen - offset < len(note):
                    #print ("\nNOTES section length mismatch!\n\t%s\n\tSection Bytes: %s\n\tStranded bytes: %s\n" % (sec, repr(notebytes), repr(notebytes[offset:])))
                    break

                offset = note.vsParse(notebytes,offset=offset)
                yield note

    def getPlatform(self):
        '''
        Return a "best effort" platform guess (envi platform name).
        ( and platform specific details if any )

        Example:
            plat = e.getPlatform()
        '''
        for note in self.getNotes():
            if note.name == 'GNU\x00' and note.ntype == 1:
                desc0 = int(note.desc[0])
                return osnotes.get(desc0,'unknown')

        return 'unknown'

    def getDynamics(self):
        '''
        Return a list of the dynamics.
        '''
        return list(self.dynamics)

    def getDynSyms(self):
        '''
        Return a list of dynamic symbol objects.
        '''
        return self.dynamic_symbols

    def getRelocs(self):
        '''
        Get the list of relocations.
        '''
        return list(self.relocs)

    def isPreLinked(self):
        '''
        Returns True if the Elf binary is prelinked.
        '''
        for dyn in self.dynamics:
            if dyn.d_tag == DT_GNU_PRELINKED:
                return True
            if dyn.d_tag == DT_GNU_CONFLICTSZ:
                return True
        return False

    def isSharedObject(self):
        '''
        Returns true if the given Elf binary is a dynamically shared
        object.
        '''
        if self.e_type == ET_DYN:
            return True
        return False

    def isExecutable(self):
        '''
        Returns true if the given Elf binary is an executable file type.
        '''
        return self.e_type == ET_EXEC

    def __repr__(self, verbose=False):
        """  
        Returns a string summary of this ELF.  
        If (verbose) the summary will include Symbols, Relocs, Dynamics and Dynamic Symbol tables
        """
        mystr = 'Elf Binary:'
        mystr+= "\n= Intimate Details:"
        mystr+= "\n==Magic:\t\t\t\t"       + self.e_ident
        mystr+= "\n==Type:\t\t\t\t\t"        + e_types.get(self.e_type)
        mystr+= "\n==Machine Arch:\t\t\t\t"  + e_machine_types.get(self.e_machine)
        mystr+= "\n==Version:\t\t\t\t%d"     % (self.e_version)
        mystr+= "\n==Entry:\t\t\t\t0x%.8x"      % (self.e_entry)
        mystr+= "\n==Program Headers(offset):\t\t%d (0x%x) bytes" % (self.e_phoff, self.e_phoff)
        mystr+= "\n==Section Headers(offset):\t\t%d (0x%x) bytes" % (self.e_shoff, self.e_shoff)
        mystr+= "\n==Flags:\t\t\t\t" + repr(self.e_flags) + " "
        mystr+= "\n==Elf Header Size:\t\t\t" + repr(self.e_ehsize) + " (" + hex(self.e_ehsize) + " bytes)"
        mystr+= "\n==Program Header Size:\t\t\t" + repr(self.e_phentsize) + " (" + hex(self.e_phentsize) + " bytes)"
        mystr+= "\n==Program Header Count:\t\t\t" + repr(self.e_phnum) + " (" + hex(self.e_phnum)+ ")"
        mystr+= "\n==Section Header Size:\t\t\t" + repr(self.e_shentsize) + " (" + hex(self.e_shentsize) + " bytes)"
        mystr+= "\n==Section Header Count:\t\t\t" + repr(self.e_shnum) + " (" + hex(self.e_shnum) + ")"
        mystr+= "\n==Section Header String Index\t\t" + repr(self.e_shstrndx) + " (" + hex(self.e_shstrndx) + " bytes)"

        mystr+= "\n\n= Sections:"
        for sec in self.sections:
            mystr+= "\n"+repr(sec)

        mystr+= "\n\n= Program Headers:"
        for ph in self.pheaders:
            mystr+= "\n"+repr(ph)

        return mystr

    def verbrepr(self):
        '''
        "Verbose" repr.  Returns a string like __repr__(), with dynamics and symbols
        '''
        mystr = repr(self)

        mystr+= "\n\n= Dynamics table:"
        for dyn in self.dynamics:
            mystr+= "\n"+repr(dyn)

        mystr+= "\n\n= Dynamic Symbols table:"
        for dyn in self.dynamic_symbols:
            mystr+= "\n"+repr(dyn)

        mystr+= "\n\n= Symbols table:"
        for sym in self.symbols:
            mystr+= "\n"+repr(sym)

        mystr+= "\n\n= Relocation table:"
        for reloc in self.relocs:
            mystr+= "\n"+repr(reloc)

        return mystr
 
    def lookupSymbolName(self, name):
        """
        Lookup symbol entries in this elf binary by name.  The result is
        a long representing the address for the given symbol. Or None if
        it's not found.
        """
        return self.symbols_by_name.get(name, None)

    def lookupSymbolAddr(self, address):
        """
        lookup symbols from this elf binary by address.
        This returns the name for the given symbol or None for not found
        """
        return self.symbols_by_addr.get(address, None)

    def getPheaders(self):
        """
        Return a list of the program headers for this elf
        """
        return list(self.pheaders)

    def addSymbol(self, symbol):
        '''
        Add a symbol to the Symbols table, along with caching symbols_by_name and symbols_by_addr
        These symbols are from ELF Sections of type SHT_SYMTAB
        '''
        self.symbols.append(symbol)
        self.symbols_by_name[symbol.getName()] = symbol
        self.symbols_by_addr[symbol.st_value] = symbol

    def getSymbols(self):
        '''
        Returns discovered Symbols (from ELF Sections)
        '''
        return self.symbols


    def getDynHdr(self):
        phdr = None
        for phdr in self.getPheaders():
            if phdr.p_type == PT_DYNAMIC:
                break
        return phdr

    def getDynBytes(self):
        '''
        Finds and returns the bytes from a Program Header of type PT_DYNAMIC
        '''
        phdr = self.getDynHdr()
        dynbytes = self.readAtOffset(phdr.p_offset, phdr.p_filesz)
        return dynbytes

    def _parseDynLinkInfo(self):
        '''
        Parse the Dynamics section and populate both self.dynamics and self.dyns
        This must be run before most Dynamic-data accessors like getDynStrTabString(), 
        getDynSymTabInfo(), etc..
        '''
        self.dyns = {}
        dynbytes = self.getDynBytes()

        while dynbytes:
            if self.bits == 32:
                dyn = Elf32Dynamic(bigend=self.bigend)
            elif self.bits == 64:
                dyn = Elf64Dynamic(bigend=self.bigend)
            else:
                raise Exception('Platform not supported: %d' % (self.bits))

            dyn.vsParse(dynbytes)

            # dump the tag/value pairs into the "dyns" dictionary.  if multiples, create a tuple
            curdyn = self.dyns.get(dyn.d_tag)
            if curdyn != None:
                self.dyns[dyn.d_tag] = (curdyn, dyn.d_value)
            else:
                self.dyns[dyn.d_tag] = dyn.d_value
            #print "dynamic: %r: 0x%x" % (dt_names.get(dyn.d_tag), dyn.d_value)

            # FIXME: storing info in both dyns{} and dynamics[].  Is this a problem?
            self.dynamics.append(dyn)
            if dyn.d_tag == DT_NULL: # Represents the end
                break
            dynbytes = dynbytes[len(dyn):]

    def _parseDynSyms(self):
        # terminate SYMTAB (SYMTABSZ doesn't actually exist)
        symtabva = self.dyns.get(DT_SYMTAB)
        nextva = 0xffffffffffffffff
        for val in self.dyns.values():
            # FIXME: make a list of valid dynamic entries... would hate for a string offset or size to somehow cut this short on smaller bins based from 0
            if val < nextva and val > symtabva:
                nextva = val
        self.dyns[HACK_SYMTABSZ] = nextva - symtabva

        # setup STRTAB for string recovery:
        strtab = self.dyns.get(DT_STRTAB) 
        strsz = self.dyns.get(DT_STRSZ)
        if strtab != None and strsz != None:
            self.setDynStrTab(strtab, strsz)

        for dyn in self.dynamics:
            if dyn.d_tag in Elf32Dynamic.has_string:
                name = self.getDynStrtabString(dyn.d_value)
                dyn.setName(name)

        # process dynamic symbol table
        symtabrva, symsz, symtabsz = self.getDynSymTabInfo()
        if symtabrva != None:
            symtab = self.readAtRva(symtabrva, symtabsz)

            sym = self._cls_symbol(bigend=self.bigend)
            count = symtabsz / symsz
            syms = self.syms = sym * count #symsz
            vstruct.VArray(elems=syms).vsParse(symtab,fast=True)

            for sym in syms:
                if not sym.st_name:
                    continue
                name = self.getDynStrtabString(sym.st_name)
                sym.setName(name)

            self.dynamic_symbols.extend(syms)

        return self.dyns

    def getDynStrTabInfo(self):
        return self.strtab

    def getDynSymTabInfo(self):
        '''
        Returns Symbol Table information (as obtained through Dynamics only)
        Assumes STRTAB immediately follows SYMTAB (to 
        returns (symtabva, symbolsz, symtabsz)
        '''
        symtabva = self.dyns.get(DT_SYMTAB)
        symsz = self.dyns.get(DT_SYMENT)
        symtabsz = self.dyns.get(HACK_SYMTABSZ)

        return symtabva, symsz, symtabsz

    def setDynStrTab(self, rva, size):
        if self.strtab != None:
            curtab = self.strtab[0]
            print('wtf?  multiple dynamic string tables?  old: 0x%x  new: 0x%x' % (curtab, rva))

        self.strtab = (rva, size)

    def getDynStrtabString(self, stroff):
        '''
        Returns a string starting at stroff
        '''
        if self.strtab == None:
            print "no dyn strtabs!"
            return ''

        strtab, strsz = self.strtab
        strings = self.readAtRva(strtab, strsz)
        strend = strings.find('\0', stroff)

        return strings[stroff:strend]

def getRelocType(val):
    return val & 0xff

def getRelocSymTabIndex(val):
    return val >> 8

