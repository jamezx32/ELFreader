#include"readelf.h"

int main(){
    const char* path = "../elftest";
    FILE* file = open_elf_file(path);
    Elf64_Ehdr* ELFhdr = read_ELFhdr(file);
    Elf64_Shdr* ELFshdr = read_shdr(ELFhdr,file);

    print_elf_detail(ELFhdr);

    print_section_detail(ELFshdr,ELFhdr,file);

    print_symtab_detail(ELFshdr,ELFhdr,file);

    symbol_revise(ELFshdr,ELFhdr, file);
    //释放动态分配的指针内存
    free(ELFhdr);
    free(ELFshdr);

    //关闭文件
    fclose(file);
    return 0;
}