---
layout: post
title:  "Pseudo VML Development"
summary: "How Pseudo VML was developed"
date: '2025-02-26 21:00:00 +0000'
category: projects
thumbnail: /assets/img/posts/code.jpg
keywords: How, Development, Dev, Pseudo-VML, PVML, Pen-Testing, Hacking
permalink: /posts/how_pseudo_vml_was_developed/
usemathjax: true
---

# Pseudo VML

Pseudo VML is a tool / library for the analysis and modification of windows executables.
The name of the library *Pseudo VML* stands for *Pseudo Virtual Machine Light*. The reason for this name is because I originally wanted to make a
virtual machine like tool, that would be able to analyse and modify, all the system calls that were being called by a particular executable.
The way I thought I'd achieve this is through a technique commonly referred to as *code caving*, within the field of malware development.

## Code Caving

Code caving is the practice of inserting code (often malicious), **in between** the instructings of an existing executable.
This is possible because of the fact that modern compilers, often don't end up optimally using the space which they've allocated within the executables
text section (the section that contains the executables code). This means that there are parts of the code that are completely unused.

This is where I first thought of adding my code which I would use to mimic the syscalls I wanted to monitor.
If you don't know how executables look under the hood, you might be wondering why we couldn't just put our code wherever you want, 
and just "move the instructions out of the way", and that is TECHNICALLY possible, but practically impossible.
This is because of the fact that most instructions requires that certain things remain a constant distance from it, or that they remain in some 
exact location within the executable. Take this simplified hello world example:

```nasm
message: 
    db "Hello World", 10

func:
    mov rax, 1
    mov rdi, 1
    mov rsi, message
    syscall
```

Let's for a second pretend that we would want to add a new function in between *message* and *func* as follows:

```nasm
message: 
    db "Hello World", 10

payload_message:
    db "Hello from Payload", 10

payload_func:
    mov rax, 1
    mov rdi, 1
    mov rsi, payload_message
    syscall

func:
    mov rax, 1
    mov rdi, 1
    mov rsi, message
    syscall
```

This would work just fine if we would do this in regular assembly, but we're in binary land now, and that's where things get a little tricky.
That's because the original function *func*, most likely relies on the message being some fixed distance from the `mov rsi, message` instruction.
This is itself due to something called position independent execution, which we don't have time to go through here, but the conclusion here is that
the instruction will look for the message "Hello World" at the offset where we've now got our own code; this is no good.

Let's look at a second example, where we have a section unused memory, represented here by the `nop` instruction.

```nasm
message: 
    db "Hello World", 10

func:
    mov rax, 1
    mov rdi, 1
    mov rsi, message
    syscall
    
    nop
    nop
    nop
    nop
    ...
```

This gives us some room to add our code that does not interfere with the rest of the executables instructions, by replacing this empty room with our payload function as follows:

```nasm
message: 
    db "Hello World", 10

func:
    mov rax, 1
    mov rdi, 1
    mov rsi, message
    syscall
    
payload_message:
    db "Hello from Payload", 10

payload_func:
    mov rax, 1
    mov rdi, 1
    mov rsi, payload_message
    syscall
```

If you're observant you can probably notice the problem with this approach; we are limited by the size of the empty memory section for our code. This imposes a huge restriction in what you're fundamentally
able to do, as well as being a major pain in the ass to deal with. Especially if you want the insertion process to be automated.
For this we will be looking into another way of getting our code into an executable, that being adding a whole new memory section into the executable and putting our code there.
But before this, it's probably a good idea to go on a tangent about how an executable is actually built up.


## The Windows PE file format

The windows PE (Portable Executable) file format, is the file format used to represent primarily *.exe* and *.dll* files. For the sake of brevity, we will be skipping simplifying this quite heavily, 
although it will still be enough information to get started in understanding how these things are made up. The general structure in order from top to bottom is as follows:

1. Dos Header
2. Dos Stub
3. NT Header
4. Section Headers
5. Sections

### Dos Header

The dos header is a bit of a historical oddity that only exists for backward compatability reasons. 
The only two parts of this header that are important for us are:

1. **Magic Number**: A two byte number that shows that this is a windows executable. Specifically it is always set to hex `0x5A4D` or "MZ" in ASCII.
2. **e_lfanew**: A "pointer" to the NT Header.

The full c structure is as follows:

```c
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```

### Dos Stub

A small DOS program that usually just prints out "This program cannot be run in dos mode".

### NT Header

The NT header has three parts:

1. **Signature**: Specfies that the executable is an NT file.
2. **File Header**: Mainly contains some section information.
3. **Optional Header**: Despite the name, this is not an optional header, as it contains most of the information required to load the executable into memory.

These are the c structures that make up the NT header:

```c
typedef struct _IMAGE_OPTIONAL_HEADER {
    //
    // Standard fields.
    //

    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;

    //
    // NT additional fields.
    //

    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
```

```c
typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
```

```c
typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```

```c
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;
```

## Section Headers

The Section headers are places one after the other, directly after the NT header. The headers contain information about their respective section; each section must have its own header.
This is the c structure:

```c
typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

## Sections

A section is just a bit of information, and they don't have a predefined structure. This is where all the data and code which makes up the executable is stored.
Some sections also have a specific predefined purposes. Most of these are not garanteed to be it's own section, or even exist at all, such as the Import Address Table (IAT), or Export Address Table (EAT)


### Adding a new Section

Now that we've gone through some of the basics around the PE file structure, we can go straight to adding our new section.
The first step in this process is to check if there is space to add a new section header. Most of the time there is some empty space between the end of the last section header, and the start of the first section. 
This is not garanteed to be large enough to fit a new section header, although it almost always is.

When we know that there is enough space, we can simply add a new section header right after the last one. We then also need to increment the `NumberOfSections` field in the NT file header, to ensure that our new header gets read.
The actual section data can be added to the end of the last section, taking into account various types of file alignment.


## Designing a Payload

Now we finally arrive at the part about this that is specific for the tool I've been developing over the past few months; the payload.
Firstly we will be going through what the design requirements for the Pseudo VML payload actually are. The requirements are as follows:

1. Windows API Calls: Needs to be able to call any function within Windows core utilities.
2. Data storage: Needs to be able to read and write data with a life time equal to that of the execution.
3. Easy Enterance / Exit: Needs to be easily entered and exited from the main execution.
4. Mostly C Compiled: Needs to be able to be written mostly in C.


### Accessing Windows API Calls

Unlike in Linux, syscalls are not directly accessible to regular user-mode processes. Instead, Windows requires that you interact with the kernel through their core utility DLLs.
The typical way an executable gets access to the functions within these DLLs, is by directly linking them into the executable, through something called the Import Table.
This is a piece of information, typically placed in it's own section, that contains all the functions the executable wishes to use, as well as which DLLs they came from.
The actual addresses of these functions are then placed into something called the Import Address Table (IAT), where they can then be used by the program.
We could therefore get access to these functions by parsing the Import Descriptors within the Import Table, before fetching the addresses of the functions from the IAT.
This will restrict our payload to only be able to use the functions that the host executable has imported. There is however a method which is both easier, and gives us access to all the functions Windows has to offer.
This is through a structure called the **Process Environment Block** or PEB.

#### PEB

The PEB is a structure containing information about the current process. Its c structure is as follows:

```c
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;
```

```c
typedef struct _PEB_LDR_DATA {
  BYTE       Reserved1[8];
  PVOID      Reserved2[3];
  LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
```

But more importantly, it also contains the base address of a DLL called **kernel32.dll**.
This DLL contains all the functions we'll need later on. The kernel32 base address resides within the third entry of the LDRs `InMemoryOrderModuleList`.
How we retrieve this base address in assembly is as follows:

```nasm
get_kernel32_base_address:
    xor rcx, rcx ; RCX = 0
    mov rax, [gs:rcx + 0x60] ; RAX = PEB
    mov rax, [rax + 0x18] ; RAX = PEB.Ldr
    mov rax, [rax + 0x10]
    mov rax, [rax]
    mov rax, [rax]
    mov rax, [rax + 0x30] ; RAX = kernel32 base address
    ret
```

The way we get the current processes base address is like this (we'll need it later):

```nasm
get_self_base_address:   
    xor rcx, rcx ; RCX = 0
    mov rax, [gs:rcx + 0x60] ; RAX = PEB
    mov rax, [rax + 0x18] ; RAX = PEB.Ldr
    mov rax, [rax + 0x10]
    mov rax, [rax + 0x30] ; RAX = self base address
    ret
```

#### Parsing Kernel32.dll

The base address of kernel32 is a pointer to the start of its DOS header, which can then be used to get the NT header. We can then find the Export Directory / Export Address Table (EAT) through the NT headers `DataDirectory`.
It's c structure is as follows:

```c
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;
    DWORD   AddressOfNames;
    DWORD   AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

By parsing this table, we can find the address of every function within kernel32. By choosing some very particular functions from this table, we can achieve our first design requirement.

#### The Big Five

The primary functions are the following:

1. LoadLibraryA: Allows us to load any DLL into memory, and get their module handle.
2. GetProcAddress: Allows us to retrieve the address of any function within any loaded library.
3. VirtualAlloc: Allows us to allocate memory.
4. VirtualFree: Allows us to free memory.

These functions give the core functionality our payload will need, and allowing us to actually interact with the kernel, any way we wish. Thereby completing our first design requirement.


### Data Storage

Once we've done all this work, parsing through kernel32s various functions to get our needed function addresses, we'd probably like to store that information somewhere, so we don't have to redo all the work we've done, 
every time we enter the payload. This is why we need a place we can write our data to, where we can come back to without the need for a pointer to the memorys address, as a pointer would just get lost every time we exit the payload,
rendering the memory unfindable.

This can be done with the help of our own executions base address, which we showed how to retrieve, earlier. We can then use this base address to parse through our own executables headers, where we can navigate our way to our payloads
section. This is where we are going to place any and all of the data that we might want to keep, such as important function addresses and DLL module handles.


### Enterance and Exit

The whole point of the Pseudo-VML payload, is to enable the modification and monitoring of the host executables various function calls, that are of interest. The way this is going to be achieved, is by simply replacing
whatever call instruction that's of interest, with a call into the corresponding modified function within our payload. We will need to be a bit careful with how we do this though, 
as whatever instruction / instructions we use for this, will need to be the exact length of whatever instruction it's replacing, so to not destroy the actual code. 
This is quite simple when the instruction to replace is smaller than or equal to the new instruction, although gets quite a bit more complicated when the inverse is true.
In assembly there is typically two ways you'll see functions being called; 
with a call instruction, or with a jump instruction. In raw machine code, there are a few different versions of these, some shorter, some longer. For simplicity's sake we'll just be going through the simple short jump for now.

#### Building a Short Jump Instruction

In order to build an instruction you much first know a little bit about **x86_64 machine code encoding**. This is basically like the *"format"* of an instruction within x86_64 machine code.
Every instruction has a slightly different way of doing things, so we'll just go through how the short jump instruction does it, and even more specifically, we will just be looking at how the *short jump with rel32* instruction does it.

The c structure of this instruction is as follows:

```c
typedef struct __attribute__((__packed__)) {
    uint8_t opcode;
    int32_t rel32;
} Instruction_CallNear;
```

From this you can see how the instruction is made up by two parts, the first of which is the opcode. The opcode in this case is a single byte, always equalling `0xE8`. This just identifies what instruction we're actually working with.
Second is the rel32, which is a 32 bit signed integer that, when added to the virtual address of the next instruction, gives you the destination virtual address of the jump instruction.
This is, as of writing done by the following function within Pseudo-VML:

```c
InstructionInfo* build_call_near(IMAGE_SECTION_HEADER* instruction_header, unsigned int instruction_rva, unsigned int function_virtual_address) {
    InstructionInfo* instruction = malloc(sizeof(InstructionInfo));
    Instruction_CallNear* raw_data = malloc(sizeof(Instruction_CallNear));
    raw_data->opcode = 0xE8;

    unsigned int inst_va = instruction_header->VirtualAddress + instruction_rva + sizeof(Instruction_JumpNear);
    unsigned int inst_fo = instruction_header->PointerToRawData + instruction_rva;
    raw_data->rel32 = function_virtual_address - inst_va;

    instruction->type = INST_TYPE_CALL_NEAR;
    instruction->raw_data = (char*)raw_data;
    instruction->data_length = sizeof(Instruction_CallNear);
    instruction->instruction_file_offset = inst_fo;
    return instruction;
}
```

This is pretty much the simplest example of an instruction builder, as this particular instruction doesn't need the actual hell hole that is R/M bytes, REX bytes or any of the various register shenanigans that exists within x86_64 machine code.

#### Nop Padding

In the case that our jump instruction we've just built is not quite large enough, we can simply pad the end of the instruction with `nop` instructions. These are simple one byte instructions, 
that only increment the instruction pointer by one (moving to the next instruction), and nothing more. The hex code for this instruction is `0x90`.

#### Parsing Executable Code

Once we are able to create our own instructions, we now need to find where to put them. A simple way of doing this is by using a tool like **PE-Bear** or even **objdump**. This is very manual however,
and with large executables, could end up taking quite a long time. This is why I ended up adding the [xed library](https://intelxed.github.io/) to Pseudo-VML. 
This library simply allows us to parse raw machine code, into individual assembly instructions. This means that we can now simply look through all the instructions, locate all the calls and jumps that are of interest.
The functions this tool looks for is specifically those that are DLL-calls. The way you identify if an instruction is a DLL-call is by, checking if the destination address of the instruction is within the IAT.
The address can then be compared with the different addresses of the IAT to locate exactly what function is being called. The way I implemented this is through something I call the **JumpTable**.

As of the time of writing, the code looks like this:

```c
void jump_table_find_references(ExeInfo* exe_info, AsmParserState* asm_state, JumpTable* jump_table) {
    for (unsigned int i = 0; i < asm_state->decoded_instructions_count; i++) {
        xed_decoded_inst_t* inst = &asm_state->decoded_instructions[i];
        xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass(inst);
        uint8_t opcode = asm_state->binary_instructions[asm_state->binary_instruction_pointers[i]];
        uint8_t modrm = xed_decoded_inst_get_modrm(inst);
        unsigned int inst_size_bytes = asm_state->instruction_lengths[i];
        unsigned int ptr = asm_state->binary_instruction_pointers[i];
        
        if (iclass == XED_ICLASS_CALL_NEAR && modrm == 0x15) {
            uint32_t rel32 = *(uint32_t*)(asm_state->binary_instructions + (ptr + 2));
            int64_t dest_va = rel32 + asm_state->header->VirtualAddress + ptr + 6;
            if (!(dest_va >= jump_table->iat_start_virtual_address &&
                    dest_va <= jump_table->iat_end_virtual_address)) {
                continue;
            }
            unsigned int jump_func_idx = get_jump_func_from_reference(jump_table, dest_va);
            JumpFunction* jump_func = &jump_table->jump_functions[jump_func_idx];
            const char* dll_name = jump_func->from_dll->name;
            const char* func_name = jump_func->from_dll->function_names[jump_func->function_index];
            unsigned int file_offset = asm_state->header->PointerToRawData + asm_state->binary_instruction_pointers[i] - asm_state->header->VirtualAddress;
            printf("\'%s\' from: \'%s\' call at op idx: %u and file offset: 0x%" PRIx32 "\n", func_name, dll_name, i, file_offset);
            
            if (jump_table->jump_reference_count >= jump_table->max_jump_reference_count) {
                printf("ERROR: Max jump reference count reached\n");
                exit(1);
            }
            JumpReference* ref = &jump_table->jump_references[jump_table->jump_reference_count];
            jump_table->jump_reference_count++;
            ref->from_header = asm_state->header;
            ref->from_fo = file_offset;
            ref->from_va = asm_state->header->VirtualAddress + asm_state->binary_instruction_pointers[i];
            ref->to_func = jump_func;
        } else if (iclass == XED_ICLASS_JMP && modrm == 0x25) {
            // NOTE(TeYo): When ever you se this, it's probably from a reference table before the IAT
            uint32_t rel32 = *(uint32_t*)(asm_state->binary_instructions + (ptr + 2));
            int64_t dest_va = rel32 + asm_state->header->VirtualAddress  + ptr + 6;
            if (!(dest_va >= jump_table->iat_start_virtual_address &&
                        dest_va <= jump_table->iat_end_virtual_address)) {
                continue;
            }
            unsigned int jump_func_idx = get_jump_func_from_reference(jump_table, dest_va);
            JumpFunction* jump_func = &jump_table->jump_functions[jump_func_idx];
            const char* dll_name = jump_func->from_dll->name;
            const char* func_name = jump_func->from_dll->function_names[jump_func->function_index];
            unsigned int file_offset = asm_state->header->PointerToRawData + asm_state->binary_instruction_pointers[i];
            printf("\'%s\' from: \'%s\' call at op idx: %u and file offset: 0x%" PRIx32 "\n", func_name, dll_name, i, file_offset);
            
            if (jump_table->jump_reference_count >= jump_table->max_jump_reference_count) {
                printf("ERROR: Max jump reference count reached\n");
                exit(1);
            }
            JumpReference* ref = &jump_table->jump_references[jump_table->jump_reference_count];
            jump_table->jump_reference_count++;
            ref->from_header = asm_state->header;
            ref->from_fo = file_offset;
            ref->from_va = asm_state->header->VirtualAddress + asm_state->binary_instruction_pointers[i];
            ref->to_func = jump_func;
        }
    }

    printf("0x%" PRIx32 " -> 0x%" PRIx32 "\n", jump_table->iat_start_virtual_address, jump_table->iat_end_virtual_address);
}
```

#### Exiting the Payload

If we are lucky with how our enterance to the payload looks, we might only need to call the `ret` instruction. If we needed to remove some instructions within the executable to make room for our enterance code, 
we will simply need to add those instructions back at the end of our payload, before the return instruction, making sure to account for the change in position if needed. In most cases, this will never have to be done.

### Compiling the Payload

This is the last step in designing a payload, actually compiling the payload itself. The way I ended up doing this is by compiling a c file as a DLL, making sure that the payload functions are exported.
All the code also needs to be compiled with **Position Independent Execution**, to ensure that it will still work after being inserted into the executable. This can be done by adding the `-fPIE` flag with gcc.
I also make sure to disable any compile-time optimisations with `-o0`, since they might end up screwing something up, which we don't want. The few things we need to be written in assembly, 
like fetching the kernel32 base address, can simply be linked with the DLL, and referenced in the code as an external symbol.
Finally there are some things we need to think about when actually writing our C code, to ensure that it works in our very particular use-case.

#### C Code Limitations

As we will only be able to make use of the code section within the compiled payload, we cannot use any C feature that would end up using any other section, particularly the **.rdata** section.
This means that we will not be able to make use of string literals, or at least not inlined ones. There is one way of getting around this, 
that being to place all the strings you want into a constant globabl variable that has been specified to be placed in the **.text** section (our payloads code section before insertion).
This is done using the following code:

```c
const char __attribute__((section(".text#"))) name_of_string[] = "Hello World";
```

As with most obscure C features, this can be quite a pain to use, which is why I instead simply use the same data storage as mentioned in a previous section of this post, to store any strings I might need.
It's not perfect, but it gets the job done.

Another big limitation is that you won't be able to include any of the standard library, as that will make use of the **.idata** section. Instead, you'll just have to use windows API functions, 
retrieved through the above mentioned process.
