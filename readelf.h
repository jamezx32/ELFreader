#include <stdio.h>
#include <elf.h>
#include <stdlib.h>
#include <inttypes.h> // 为了使用PRIx64宏
#include <string.h>


extern void print_elf_detail(const Elf64_Ehdr *ELFhdr);

extern FILE* open_elf_file(const char* path);

extern Elf64_Ehdr* read_ELFhdr(FILE *file);

extern Elf64_Shdr* read_shdr(Elf64_Ehdr* ELFhdr,FILE* file);

extern void print_section_detail(const Elf64_Shdr *ELFshdr,const Elf64_Ehdr *ELFhdr,FILE *file);

extern void print_symtab_detail (const Elf64_Shdr *ELFshdr,const Elf64_Ehdr *ELFhdr,FILE *file);

extern void symbol_revise(const Elf64_Shdr *ELFshdr,const Elf64_Ehdr *ELFhdr,FILE *file);