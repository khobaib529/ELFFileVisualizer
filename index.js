let current_elf_data = null;
let tooltip = null;
let file_buffer = null;

const section_colors = {
    'SHT_PROGBITS': 'bg-blue-600',
    'SHT_NOBITS': 'bg-purple-600',
    'SHT_SYMTAB': 'bg-green-600',
    'SHT_STRTAB': 'bg-yellow-600',
    'SHT_DYNSYM': 'bg-pink-600',
    'SHT_DYNAMIC': 'bg-red-600',
    'SHT_REL': 'bg-indigo-600',
    'SHT_RELA': 'bg-orange-600',
    'SHT_NOTE': 'bg-teal-600',
    'SHT_HASH': 'bg-lime-600',
    'SHT_INIT_ARRAY': 'bg-sky-600',
    'SHT_FINI_ARRAY': 'bg-rose-600',
    'SHT_PREINIT_ARRAY': 'bg-fuchsia-600',
    'SHT_GROUP': 'bg-gray-500',
    'SHT_SYMTAB_SHNDX': 'bg-green-400',
    'default': 'bg-gray-600'
};

const segment_colors = {
    'PT_LOAD': 'bg-emerald-600',
    'PT_DYNAMIC': 'bg-amber-600',
    'PT_INTERP': 'bg-cyan-600',
    'PT_NOTE': 'bg-rose-600',
    'PT_PHDR': 'bg-violet-600',
    'PT_TLS': 'bg-lime-600',
    'PT_GNU_EH_FRAME': 'bg-sky-600',
    'PT_GNU_STACK': 'bg-indigo-600',
    'PT_GNU_RELRO': 'bg-pink-600',
    'default': 'bg-slate-600'
};

document.getElementById('fileInput').addEventListener('change', handle_file_select);

function handle_file_select(event) {
    const file = event.target.files[0];
    if (!file) return;

    document.getElementById('fileName').textContent = file.name;
    document.getElementById('fileSize').textContent = `${(file.size / 1024).toFixed(2)} KB`;
    document.getElementById('fileInfo').classList.remove('hidden');
    document.getElementById('results').classList.add('hidden');
    document.getElementById('errorDiv').classList.add('hidden');
    
    const reader = new FileReader();
    reader.onload = function(e) {
        file_buffer = e.target.result;
        setTimeout(() => {
            try {
                current_elf_data = ELFParser.parse(file_buffer);
                display_elf_data(current_elf_data);
                document.getElementById('results').classList.remove('hidden');
            } catch (error) {
                console.error("Error parsing ELF file:", error);
                document.getElementById('errorMessage').textContent = error.message;
                document.getElementById('errorDiv').classList.remove('hidden');
            } finally {
                document.getElementById('fileInfo').classList.add('hidden');
            }
        }, 50); 
    };
    reader.onerror = function() {
        console.error("Error reading file.");
        document.getElementById('errorMessage').textContent = "Error reading the selected file.";
        document.getElementById('errorDiv').classList.remove('hidden');
        document.getElementById('fileInfo').classList.add('hidden');
    };
    reader.readAsArrayBuffer(file);
}

function display_elf_data(elf_data) {
    display_elf_header(elf_data.elf_header);
    display_section_layout(elf_data);
    display_program_headers(elf_data.program_headers);
    display_section_headers(elf_data.section_headers);
}

function display_elf_header(header) {
    const container = document.getElementById('elfHeader');
    container.innerHTML = '';
    const fields = [
        { label: 'Magic', value: header.e_ident }, { label: 'Type', value: header.e_type },
        { label: 'Machine', value: header.e_machine }, { label: 'Version', value: header.e_version },
        { label: 'Entry Point', value: `0x${header.e_entry.toString(16)}` },
        { label: 'PH Offset', value: `0x${header.e_phoff.toString(16)}` },
        { label: 'SH Offset', value: `0x${header.e_shoff.toString(16)}` },
        { label: 'Flags', value: `0x${header.e_flags.toString(16)}` },
        { label: 'Header Size', value: `${header.e_ehsize}B` },
        { label: 'PH Size', value: `${header.e_phentsize}B` }, { label: 'PH Count', value: header.e_phnum },
        { label: 'SH Size', value: `${header.e_shentsize}B` }, { label: 'SH Count', value: header.e_shnum },
        { label: 'SH String Table Index', value: header.e_shstrndx }
    ];
    fields.forEach(field => {
        const div = document.createElement('div');
        div.className = 'bg-gray-800/50 border border-gray-700 rounded p-3';
        div.innerHTML = `
            <div class="text-xs text-gray-400 mb-1">${field.label}</div>
            <div class="text-sm text-gray-200 ${field.label === 'Magic' ? 'break-all' : ''}">${field.value}</div>
        `;
        container.appendChild(div);
    });
}

function display_section_layout(elf_data) {
    const container = document.getElementById('sectionLayout');
    const legend = document.getElementById('sectionLegend');
    container.innerHTML = ''; 
    legend.innerHTML = '';    

    if (!file_buffer || file_buffer.byteLength === 0) {
        container.innerHTML = '<p class="text-gray-500 text-xs p-2">File data not available or file is empty.</p>';
        return;
    }
    const total_file_size = file_buffer.byteLength;

    const sections_to_display = elf_data.section_headers.filter(s =>
        s.sh_type !== 'SHT_NULL' &&
        s.sh_type !== 'SHT_NOBITS' &&
        s.sh_size > 0 &&
        // typeof s.sh_offset !== 'undefined' && // Removed: Assumed offset is present or parseInt handles it
        parseInt(s.sh_offset, 16) < total_file_size 
    );

    sections_to_display.sort((a, b) => {
        const offset_a = parseInt(a.sh_offset, 16);
        const offset_b = parseInt(b.sh_offset, 16);
        if (offset_a !== offset_b) return offset_a - offset_b;
        return a.sh_size - b.sh_size; 
    });

    if (sections_to_display.length === 0) {
        container.innerHTML = '<p class="text-gray-500 text-xs p-2">No sections with file content to display.</p>';
        return;
    }

    const file_layout_bar = document.createElement('div');
    file_layout_bar.className = 'h-8 bg-gray-800 rounded relative overflow-hidden';
    file_layout_bar.style.minWidth = '200px'; 

    sections_to_display.forEach((section) => {
        const offset = parseInt(section.sh_offset, 16);
        const size_in_file = section.sh_size;

        const left_percent = (offset / total_file_size) * 100;
        let width_percent = (size_in_file / total_file_size) * 100;

        // Removed minimum visibility enhancement: if (width_percent > 0 && width_percent < 0.1) width_percent = 0.1;
        if (left_percent + width_percent > 100) width_percent = 100 - left_percent;
        // Removed redundant negative width check: if (width_percent < 0) width_percent = 0;


        const section_type_str = section.sh_type || 'default';
        const color_class = section_colors[section_type_str] || section_colors.default;

        const bar_segment = document.createElement('div');
        bar_segment.className = `${color_class} layout-segment cursor-pointer hover:brightness-110 transition-all`;
        bar_segment.style.position = 'absolute';
        bar_segment.style.left = `${left_percent}%`;
        bar_segment.style.width = `${width_percent}%`;
        bar_segment.style.height = '100%';
        
        bar_segment.addEventListener('mouseenter', (e) => show_tooltip(e, section, 'section'));
        bar_segment.addEventListener('mouseleave', hide_tooltip);
        bar_segment.addEventListener('mousemove', (e) => update_tooltip_position(e));

        file_layout_bar.appendChild(bar_segment);
    });

    container.appendChild(file_layout_bar);

    const legend_types = new Set();
    sections_to_display.forEach(s => legend_types.add(s.sh_type || 'default'));
    legend_types.forEach(type => {
        const legend_item = document.createElement('div');
        legend_item.className = 'flex items-center';
        legend_item.innerHTML = `
            <div class="w-3 h-3 ${section_colors[type] || section_colors.default} rounded mr-2"></div>
            <span class="text-gray-300">${type}</span>
        `;
        legend.appendChild(legend_item);
    });
}

function display_program_headers(programs) {
    const container = document.getElementById('programHeaders');
    document.getElementById('phCount').textContent = `${programs.length}`;
    container.innerHTML = '';

    programs.forEach((program, index) => {
        const type = program.p_type.replace('UNKNOWN_PT(', '').replace(')', '');
        const color_class = segment_colors[type] || segment_colors.default;
        
        const div = document.createElement('div');
        div.className = 'bg-gray-800/30 border border-gray-700 rounded p-4 hover:bg-gray-800/50 transition-colors';
        div.innerHTML = `
            <div class="flex items-center justify-between mb-3">
                <h3 class="font-medium flex items-center text-gray-200">
                    <span class="w-2 h-2 ${color_class} rounded-full mr-2"></span>
                    ${program.p_type}
                </h3>
                <span class="text-xs text-gray-500">#${index}</span>
            </div>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                <div><span class="text-gray-400">Offset:</span> <span class="text-gray-200">0x${parseInt(program.p_offset,16).toString(16)}</span></div>
                <div><span class="text-gray-400">VAddr:</span> <span class="text-gray-200">0x${parseInt(program.p_vaddr,16).toString(16)}</span></div>
                <div><span class="text-gray-400">File Size:</span> <span class="text-gray-200">${program.p_filesz}B</span></div>
                <div><span class="text-gray-400">Mem Size:</span> <span class="text-gray-200">${program.p_memsz}B</span></div>
                <div><span class="text-gray-400">PAddr:</span> <span class="text-gray-200">0x${parseInt(program.p_paddr,16).toString(16)}</span></div>
                <div><span class="text-gray-400">Flags:</span> <span class="text-gray-200">${program.p_flags}</span></div>
                <div><span class="text-gray-400">Align:</span> <span class="text-gray-200">${program.p_align}</span></div>
            </div>
        `;
        container.appendChild(div);
    });
}

function display_section_headers(sections) {
    const container = document.getElementById('sectionHeaders');
    document.getElementById('shCount').textContent = `${sections.length}`;
    container.innerHTML = '';

    sections.forEach((section, index) => {
        const section_type = section.sh_type || 'default';
        const color_class = section_colors[section_type] || section_colors.default;
        
        const div = document.createElement('div');
        div.className = 'bg-gray-800/30 border border-gray-700 rounded p-4 hover:bg-gray-800/50 transition-colors';
        div.innerHTML = `
            <div class="flex items-center justify-between mb-3">
                <h3 class="font-medium flex items-center text-gray-200">
                    <span class="w-2 h-2 ${color_class} rounded-full mr-2"></span>
                    ${section.sh_name_str || `Section ${index}`}
                </h3>
                <div class="flex items-center space-x-2">
                    <span class="text-xs bg-gray-700 text-gray-300 px-2 py-1 rounded">${section.sh_type}</span>
                    <span class="text-xs text-gray-500">#${index}</span>
                </div>
            </div>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                <div><span class="text-gray-400">Address:</span> <span class="text-gray-200">0x${parseInt(section.sh_addr,16).toString(16)}</span></div>
                <div><span class="text-gray-400">Offset:</span> <span class="text-gray-200">0x${parseInt(section.sh_offset,16).toString(16)}</span></div>
                <div><span class="text-gray-400">Size:</span> <span class="text-gray-200">${section.sh_size}B</span></div>
                <div><span class="text-gray-400">Align:</span> <span class="text-gray-200">${section.sh_addralign}</span></div>
                <div><span class="text-gray-400">Flags:</span> <span class="text-gray-200">${section.sh_flags || 'none'}</span></div>
                <div><span class="text-gray-400">Link:</span> <span class="text-gray-200">${section.sh_link}</span></div>
                <div><span class="text-gray-400">Info:</span> <span class="text-gray-200">${section.sh_info}</span></div>
                <div><span class="text-gray-400">Entry Size:</span> <span class="text-gray-200">${section.sh_entsize}</span></div>
            </div>
        `;
        container.appendChild(div);
    });
}

function show_tooltip(event, data, type) {
    hide_tooltip();
    tooltip = document.createElement('div');
    tooltip.className = 'tooltip';
    
    if (type === 'section') {
        const size_kb = (data.sh_size / 1024).toFixed(1);
        const section_name = data.sh_name_str || `Section #${current_elf_data.section_headers.indexOf(data)}`;
        tooltip.innerHTML = `
            <div style="color: #60a5fa; font-weight: 600; margin-bottom: 6px; font-size: 13px;">${section_name}</div>
            <div style="color: #a3a3a3; font-size: 11px; margin-bottom: 3px;">Type: <span style="color: #e5e7eb; font-weight: 500;">${data.sh_type}</span></div>
            <div style="color: #a3a3a3; font-size: 11px; margin-bottom: 3px;">Address: <span style="color: #e5e7eb; font-weight: 500;">0x${parseInt(data.sh_addr,16).toString(16)}</span></div>
            <div style="color: #a3a3a3; font-size: 11px; margin-bottom: 3px;">Offset: <span style="color: #e5e7eb; font-weight: 500;">0x${parseInt(data.sh_offset,16).toString(16)}</span></div>
            <div style="color: #a3a3a3; font-size: 11px;">Size: <span style="color: #e5e7eb; font-weight: 500;">${data.sh_size} bytes (${size_kb} KB)</span></div>
        `;
    } else {
        const file_size_kb = (data.p_filesz / 1024).toFixed(1);
        const mem_size_kb = (data.p_memsz / 1024).toFixed(1);
        const segment_type = data.p_type.replace('UNKNOWN_PT(', '').replace(')', '');
        tooltip.innerHTML = `
            <div style="color: #fbbf24; font-weight: 600; margin-bottom: 6px; font-size: 13px;">${segment_type} Segment</div>
            <div style="color: #a3a3a3; font-size: 11px; margin-bottom: 3px;">Virtual Addr: <span style="color: #e5e7eb; font-weight: 500;">0x${parseInt(data.p_vaddr,16).toString(16)}</span></div>
            <div style="color: #a3a3a3; font-size: 11px; margin-bottom: 3px;">File Offset: <span style="color: #e5e7eb; font-weight: 500;">0x${parseInt(data.p_offset,16).toString(16)}</span></div>
            <div style="color: #a3a3a3; font-size: 11px; margin-bottom: 3px;">File Size: <span style="color: #e5e7eb; font-weight: 500;">${data.p_filesz} bytes (${file_size_kb} KB)</span></div>
            <div style="color: #a3a3a3; font-size: 11px; margin-bottom: 3px;">Memory Size: <span style="color: #e5e7eb; font-weight: 500;">${data.p_memsz} bytes (${mem_size_kb} KB)</span></div>
            <div style="color: #a3a3a3; font-size: 11px;">Flags: <span style="color: #e5e7eb; font-weight: 500;">${data.p_flags}</span></div>
        `;
    }
    
    document.body.appendChild(tooltip);
    update_tooltip_position(event);
}

function update_tooltip_position(event) {
    if (!tooltip) return;
    const mouseX = event.clientX;
    const mouseY = event.clientY;
    const tooltipRect = tooltip.getBoundingClientRect();
    const windowWidth = window.innerWidth;
    const windowHeight = window.innerHeight;
    let x = mouseX + 15; 
    let y = mouseY - tooltipRect.height - 15; 
    if (x + tooltipRect.width > windowWidth -10) {
        x = mouseX - tooltipRect.width - 15;
    }
    if (y < 10) {
        y = mouseY + 15;
            if (y + tooltipRect.height > windowHeight - 10) {
            y = windowHeight - tooltipRect.height - 10;
        }
    }
    if (x < 10) x = 10;
    tooltip.style.left = `${x}px`;
    tooltip.style.top = `${y}px`;
}

function hide_tooltip() {
    if (tooltip) {
        tooltip.remove();
        tooltip = null;
    }
}

function toggle_section(content_id, toggle_id) {
    const content = document.getElementById(content_id);
    const toggle = document.getElementById(toggle_id);
    const is_collapsed = content.style.maxHeight === '0px' || content.classList.contains('collapsed-explicitly');
    
    if (is_collapsed) {
        content.classList.remove('collapsed-explicitly');
        content.style.maxHeight = content.scrollHeight + 'px';
        content.style.opacity = '1';
        toggle.style.transform = 'rotate(0deg)';
        setTimeout(() => {
            if (!(content.style.maxHeight === '0px')) {
                    content.style.maxHeight = 'none';
            }
        }, 210);
    } else {
        content.style.maxHeight = content.scrollHeight + 'px';
        requestAnimationFrame(() => {
            content.style.maxHeight = '0px';
            content.style.opacity = '0';
        });
        toggle.style.transform = 'rotate(-90deg)';
        content.classList.add('collapsed-explicitly');
    }
}
