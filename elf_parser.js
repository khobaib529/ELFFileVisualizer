// JavaScript implementation for parsing ELF (Executable and Linkable Format) files from a buffer.
// This parser takes an Buffer containing the binary data of an ELF file as input
// and returns a JavaScript object (JSON structure) representing the file's header,
// program headers, and section headers.
//
// The JSON output provides a structured view of the ELF file's components, including:
// - elf_header: Contains information from the ELF header, such as entry point, file type, and architecture.
// - program_headers: An array of program header entries, describing the segments of the ELF file.
// - section_headers: An array of section header entries, providing details about the different sections within the file.
//
// Example of the JSON structure:
/*
{
  "elf_header": {
    "e_ident": "7f454c46020101030000000000000000", // Magic number and other identification
    "e_type": "ET_EXEC",                            // Object file type (e.g., executable, shared object)
    "e_machine": "EM_X86_64",                      // Target architecture
    "e_version": 1,
    "e_entry": "0x0000000000401790",             // Virtual address of entry point
    "e_phoff": "0x0000000000000040",             // Program header table file offset
    "e_shoff": "0x00000000000bf4d0",             // Section header table file offset
    "e_flags": "0x00000000",
    "e_ehsize": 64,                               // ELF header size
    "e_phentsize": 56,                            // Size of program header entry
    "e_phnum": 10,                                // Number of program header entries
    "e_shentsize": 64,                            // Size of section header entry
    "e_shnum": 28,                                // Number of section header entries
    "e_shstrndx": 27                              // Section header string table index
  },
  "program_headers": [
    {
      "p_type": "PT_NOTE",                         // Segment type
      "p_offset": "0x0000000000000270",           // Segment file offset
      "p_vaddr": "0x0000000000400270",            // Segment virtual address
      "p_paddr": "0x0000000000400270",            // Segment physical address
      "p_filesz": 48,                             // Segment size in file
      "p_memsz": 48,                              // Segment size in memory
      "p_flags": "READ",                          // Segment flags (read, write, execute)
      "p_align": 8,
      "contents": "040000002000000005000000474e5500020000c0040000000300000000000000028000c0040000000100000000000000" // Raw segment data in hex
    },
    // ... other program headers
  ],
  "section_headers": [
    {
      "sh_name": 27,                               // Section name (index into section header string table)
      "sh_type": "SHT_NOTE",                       // Section type
      "sh_flags": "alloc",                       // Section flags (e.g., allocated in memory)
      "sh_addr": "0x0000000000400270",            // Section virtual address
      "sh_offset": "0x0000000000000270",           // Section file offset
      "sh_size": 48,                              // Section size in file
      "sh_link": 0,
      "sh_info": 0,
      "sh_addralign": 8,
      "sh_entsize": 0,
      "contents": "040000002000000005000000474e5500020000c0040000000300000000000000028000c0040000000100000000000000", // Raw section data in hex
      "sh_name_str": ".note.gnu.property"         // Resolved section name from string table
    },
    // ... other sections
  ]
}
*/

class ELFStringTableReader {
    constructor(hex_string) {
        this.buffer = this.hex_string_to_buffer(hex_string);
        this.data_view = new DataView(this.buffer);
    }

    hex_string_to_buffer(hex_string) {
        const byte_length = hex_string.length / 2;
        const buffer = new ArrayBuffer(byte_length);
        const view = new Uint8Array(buffer);
        for (let i = 0; i < byte_length; i++) {
            view[i] = parseInt(hex_string.substring(i * 2, i * 2 + 2), 16);
        }
        return buffer;
    }

    read_null_terminated_string(offset) {
        let result = '';
        let index = offset;
        const bytes = new Uint8Array(this.buffer);
        while (index < bytes.length) {
            const byte = bytes[index];
            if (byte === 0) {
                break;
            }
            result += String.fromCharCode(byte);
            index++;
        }
        return result;
    }
}

class ELFConstants {
    // ELF Header Types
    static ELF_TYPES = {
        0: 'ET_NONE',
        1: 'ET_REL',
        2: 'ET_EXEC',
        3: 'ET_DYN',
        4: 'ET_CORE',
        0xff00: 'ET_LOPROC',
        0xffff: 'ET_HIPROC'
    };
    
    // Machine Types
    static ELF_MACHINES = {
        0: 'EM_NONE',
        1: 'EM_M32',
        2: 'EM_SPARC',
        3: 'EM_386',
        4: 'EM_68K',
        5: 'EM_88K',
        7: 'EM_860',
        8: 'EM_MIPS',
        20: 'EM_PPC',
        21: 'EM_PPC64',
        40: 'EM_ARM',
        50: 'EM_IA_64',
        62: 'EM_X86_64',
        183: 'EM_AARCH64',
        243: 'EM_RISCV'
    };
    
    // Program Header Types
    static PROGRAM_TYPES = {
        0: 'PT_NULL',
        1: 'PT_LOAD',
        2: 'PT_DYNAMIC',
        3: 'PT_INTERP',
        4: 'PT_NOTE',
        5: 'PT_SHLIB',
        6: 'PT_PHDR',
        7: 'PT_TLS',
        0x60000000: 'PT_LOOS',
        0x6474e550: 'PT_GNU_EH_FRAME',
        0x6474e551: 'PT_GNU_STACK',
        0x6474e552: 'PT_GNU_RELRO',
        0x6fffffff: 'PT_HIOS',
        0x70000000: 'PT_LOPROC',
        0x7fffffff: 'PT_HIPROC'
    };
    
    // Program Header Flags
    static PROGRAM_FLAGS = {
        1: 'PF_X',    // Execute
        2: 'PF_W',    // Write
        4: 'PF_R'     // Read
    };
    
    // Section Header Types
    static SECTION_TYPES = {
        0: 'SHT_NULL',
        1: 'SHT_PROGBITS',
        2: 'SHT_SYMTAB',
        3: 'SHT_STRTAB',
        4: 'SHT_RELA',
        5: 'SHT_HASH',
        6: 'SHT_DYNAMIC',
        7: 'SHT_NOTE',
        8: 'SHT_NOBITS',
        9: 'SHT_REL',
        10: 'SHT_SHLIB',
        11: 'SHT_DYNSYM',
        14: 'SHT_INIT_ARRAY',
        15: 'SHT_FINI_ARRAY',
        16: 'SHT_PREINIT_ARRAY',
        17: 'SHT_GROUP',
        18: 'SHT_SYMTAB_SHNDX',
        0x60000000: 'SHT_LOOS',
        0x6ffffff6: 'SHT_GNU_HASH',
        0x6ffffff7: 'SHT_GNU_LIBLIST',
        0x6ffffff8: 'SHT_CHECKSUM',
        0x6ffffffd: 'SHT_GNU_verdef',
        0x6ffffffe: 'SHT_GNU_verneed',
        0x6fffffff: 'SHT_GNU_versym',
        0x70000000: 'SHT_LOPROC',
        0x7fffffff: 'SHT_HIPROC'
    };
    
    // Section Header Flags
    static SECTION_FLAGS = {
        0x1: 'SHF_WRITE',
        0x2: 'SHF_ALLOC',
        0x4: 'SHF_EXECINSTR',
        0x10: 'SHF_MERGE',
        0x20: 'SHF_STRINGS',
        0x40: 'SHF_INFO_LINK',
        0x80: 'SHF_LINK_ORDER',
        0x100: 'SHF_OS_NONCONFORMING',
        0x200: 'SHF_GROUP',
        0x400: 'SHF_TLS',
        0x0ff00000: 'SHF_MASKOS',
        0xf0000000: 'SHF_MASKPROC'
    };
    
    static convert_elf_type(value) {
        return this.ELF_TYPES[value] || `UNKNOWN_TYPE(${value})`;
    }
    
    static convert_machine_type(value) {
        return this.ELF_MACHINES[value] || `UNKNOWN_MACHINE(${value})`;
    }
    
    static convert_program_type(value) {
        return this.PROGRAM_TYPES[value] || `UNKNOWN_PT(0x${value.toString(16)})`;
    }
    
    static convert_program_flags(value) {
        const flags = [];
        if (value & 4) flags.push('READ');
        if (value & 2) flags.push('WRITE');
        if (value & 1) flags.push('EXECUTE');
        return flags.length > 0 ? flags.join('|') : 'none';
    }
    
    static convert_section_type(value) {
        return this.SECTION_TYPES[value] || `UNKNOWN_SHT(0x${value.toString(16)})`;
    }
    
    static convert_section_flags(value) {
        const flags = [];
        
        for (const [flag_val, flag_name] of Object.entries(this.SECTION_FLAGS)) {
            const flag_num = parseInt(flag_val);
            if (value & flag_num) {
                flags.push(flag_name.toLowerCase().replace('shf_', ''));
            }
        }
        
        return flags.length > 0 ? flags.join('|') : 'none';
    }
    
    static format_hex_address(value, is_64_bit = false) {
        if (typeof value === 'string' && value.startsWith('0x')) {
            return value;
        }
        const width = is_64_bit ? 16 : 8;
        return '0x' + value.toString(16).padStart(width, '0');
    }
    
    static format_hex_value(value) {
        if (typeof value === 'string' && value.startsWith('0x')) {
            return value;
        }
        return '0x' + value.toString(16).padStart(8, '0');
    }
}

class ELFParser {
    static parse(buffer) {
        const view = new DataView(buffer);
        const parser = new ELFParser(view);

        const parsed_elf =  {
            elf_header: parser._parse_elf_header(),
            program_headers: parser._parse_program_headers(),
            section_headers: parser._parse_section_headers()
        };

        const shstrndx = parsed_elf.elf_header.e_shstrndx;
        const elf_strtab_reader = new ELFStringTableReader(parsed_elf.section_headers[shstrndx].contents);
        parsed_elf.section_headers.forEach(section_header => {
            section_header["sh_name_str"] = elf_strtab_reader.read_null_terminated_string(section_header.sh_name);
        });
        return parsed_elf;
    }
    
    constructor(data_view) {
        this.view = data_view;
        this.is_64_bit = false;
        this.is_little_endian = true;
        this.elf_header = null;
    }
    
    _parse_elf_header() {
        // Parse ELF identification
        const e_ident = this._read_bytes(0, 16);
        const e_ident_hex = this._read_bytes_hex(0, 16);
        
        // Check if it's a valid ELF file
        if (e_ident_hex.substring(0, 8) !== '7f454c46') {
            throw new Error('Not a valid ELF file');
        }
        
        // Determine architecture and endianness
        const ei_class = new Uint8Array(e_ident)[4];
        const ei_data = new Uint8Array(e_ident)[5];
        
        this.is_64_bit = ei_class === 2;
        this.is_little_endian = ei_data === 1;
        
        let offset = 16;
        
        const e_type = this._read_uint16(offset);
        offset += 2;
        
        const e_machine = this._read_uint16(offset);
        offset += 2;
        
        const e_version = this._read_uint32(offset);
        offset += 4;
        
        const e_entry = this.is_64_bit ? this._read_uint64(offset) : this._read_uint32(offset);
        offset += this.is_64_bit ? 8 : 4;
        
        const e_phoff = this.is_64_bit ? this._read_uint64(offset) : this._read_uint32(offset);
        offset += this.is_64_bit ? 8 : 4;
        
        const e_shoff = this.is_64_bit ? this._read_uint64(offset) : this._read_uint32(offset);
        offset += this.is_64_bit ? 8 : 4;
        
        const e_flags = this._read_uint32(offset);
        offset += 4;
        
        const e_ehsize = this._read_uint16(offset);
        offset += 2;
        
        const e_phentsize = this._read_uint16(offset);
        offset += 2;
        
        const e_phnum = this._read_uint16(offset);
        offset += 2;
        
        const e_shentsize = this._read_uint16(offset);
        offset += 2;
        
        const e_shnum = this._read_uint16(offset);
        offset += 2;
        
        const e_shstrndx = this._read_uint16(offset);
        
        this.elf_header = {
            e_ident: e_ident_hex,
            e_type: ELFConstants.convert_elf_type(e_type),
            e_machine: ELFConstants.convert_machine_type(e_machine),
            e_version,
            e_entry: ELFConstants.format_hex_address(e_entry, this.is_64_bit),
            e_phoff: ELFConstants.format_hex_address(e_phoff, this.is_64_bit),
            e_shoff: ELFConstants.format_hex_address(e_shoff, this.is_64_bit),
            e_flags: ELFConstants.format_hex_value(e_flags),
            e_ehsize,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx
        };
        
        return this.elf_header;
    }
    
    _parse_program_headers() {
        if (!this.elf_header) {
            throw new Error('ELF header must be parsed first');
        }
        
        const headers = [];
        const ph_offset = parseInt(this.elf_header.e_phoff, 16);
        const ph_entsize = this.elf_header.e_phentsize;
        const ph_num = this.elf_header.e_phnum;
        
        for (let i = 0; i < ph_num; i++) {
            const offset = ph_offset + (i * ph_entsize);
            headers.push(this._parse_single_program_header(offset));
        }
        
        return headers;
    }
    
    _parse_single_program_header(offset) {
        const p_type = this._read_uint32(offset);
        offset += 4;
        
        let p_flags, p_offset_val, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
        
        if (this.is_64_bit) {
            p_flags = this._read_uint32(offset);
            offset += 4;
            
            p_offset_val = this._read_uint64(offset);
            offset += 8;
            
            p_vaddr = this._read_uint64(offset);
            offset += 8;
            
            p_paddr = this._read_uint64(offset);
            offset += 8;
            
            p_filesz = this._read_uint64(offset);
            offset += 8;
            
            p_memsz = this._read_uint64(offset);
            offset += 8;
            
            p_align = this._read_uint64(offset);
        } else {
            p_offset_val = this._read_uint32(offset);
            offset += 4;
            
            p_vaddr = this._read_uint32(offset);
            offset += 4;
            
            p_paddr = this._read_uint32(offset);
            offset += 4;
            
            p_filesz = this._read_uint32(offset);
            offset += 4;
            
            p_memsz = this._read_uint32(offset);
            offset += 4;
            
            p_flags = this._read_uint32(offset);
            offset += 4;
            
            p_align = this._read_uint32(offset);
        }
        
        return {
            p_type: ELFConstants.convert_program_type(p_type),
            p_offset: ELFConstants.format_hex_address(p_offset_val, this.is_64_bit),
            p_vaddr: ELFConstants.format_hex_address(p_vaddr, this.is_64_bit),
            p_paddr: ELFConstants.format_hex_address(p_paddr, this.is_64_bit),
            p_filesz,
            p_memsz,
            p_flags: ELFConstants.convert_program_flags(p_flags),
            p_align,
            contents: this._read_bytes_hex(Number(p_offset_val), Number(p_filesz))
        };
    }
    
    _parse_section_headers() {
        if (!this.elf_header) {
            throw new Error('ELF header must be parsed first');
        }
        
        const headers = [];
        const sh_offset = parseInt(this.elf_header.e_shoff, 16);
        const sh_entsize = this.elf_header.e_shentsize;
        const sh_num = this.elf_header.e_shnum;
        
        for (let i = 0; i < sh_num; i++) {
            const offset = sh_offset + (i * sh_entsize);
            headers.push(this._parse_single_section_header(offset));
        }
        
        return headers;
    }
    
    _parse_single_section_header(offset) {
        const sh_name = this._read_uint32(offset);
        offset += 4;
        
        const sh_type = this._read_uint32(offset);
        offset += 4;

        const sh_flags = this.is_64_bit ? this._read_uint64(offset) : this._read_uint32(offset);
        offset += this.is_64_bit ? 8 : 4;
        
        const sh_addr = this.is_64_bit ? this._read_uint64(offset) : this._read_uint32(offset);
        offset += this.is_64_bit ? 8 : 4;
        
        const sh_offset_val = this.is_64_bit ? this._read_uint64(offset) : this._read_uint32(offset);
        offset += this.is_64_bit ? 8 : 4;
        
        const sh_size = this.is_64_bit ? this._read_uint64(offset) : this._read_uint32(offset);
        offset += this.is_64_bit ? 8 : 4;
        
        const sh_link = this._read_uint32(offset);
        offset += 4;
        
        const sh_info = this._read_uint32(offset);
        offset += 4;
        
        const sh_addralign = this.is_64_bit ? this._read_uint64(offset) : this._read_uint32(offset);
        offset += this.is_64_bit ? 8 : 4;
        
        const sh_entsize = this.is_64_bit ? this._read_uint64(offset) : this._read_uint32(offset);

        return {
            sh_name,
            sh_type: ELFConstants.convert_section_type(sh_type),
            sh_flags: ELFConstants.convert_section_flags(sh_flags),
            sh_addr: ELFConstants.format_hex_address(sh_addr, this.is_64_bit),
            sh_offset: ELFConstants.format_hex_address(sh_offset_val, this.is_64_bit),
            sh_size,
            sh_link,
            sh_info,
            sh_addralign,
            sh_entsize,
            contents: this._read_bytes_hex(Number(sh_offset_val), Number(sh_size))
        };
    }

    _read_bytes_hex(offset, size) {
        let hex_string = '';
        for (let i = 0; i < size; i++) {
            const byte = this.view.getUint8(offset + i);
            const hex_byte = byte.toString(16).padStart(2, '0');
            hex_string += hex_byte;
        }
        // console.log(hex_string);
        return hex_string;
    }

    _read_uint16(offset) {
        return this.view.getUint16(offset, this.is_little_endian);
    }
    
    _read_uint32(offset) {
        return this.view.getUint32(offset, this.is_little_endian);
    }
    
    _read_uint64(offset) {
        // JavaScript doesn't have native 64-bit integers, so we'll read as two 32-bit values
        const low = this.view.getUint32(offset, this.is_little_endian);
        const high = this.view.getUint32(offset + 4, this.is_little_endian);
        
        if (this.is_little_endian) {
            return (high * 0x100000000) + low;
        } else {
            return (low * 0x100000000) + high;
        }
    }
    
    _read_bytes(offset, length) {
        return this.view.buffer.slice(offset, offset + length);
    }
    
    _format_hex(value) {
        return ELFConstants.format_hex_address(value, this.is_64_bit);
    }
}
