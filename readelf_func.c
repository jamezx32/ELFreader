#include "readelf.h"

//打开ELF文件
FILE* open_elf_file(const char* path) {
    FILE *file = fopen(path,"rb+");
    if(file == NULL) {
        perror("Error opening ELF file");
        exit(EXIT_FAILURE);
    }
    return file;
}

//读入ELF头
Elf64_Ehdr* read_ELFhdr(FILE *file) {//只有该结构体类型的指针 才能指向该结构体 解释指内存中的含义
    Elf64_Ehdr *ELFhdr;
    ELFhdr = (Elf64_Ehdr *) malloc(sizeof(Elf64_Ehdr));//动态分配内存
    size_t Ehdr_count = fread(ELFhdr, sizeof(Elf64_Ehdr), 1, file);//  将文件中的数据读入 结构体指针指向的那块 使用malloc函数动态分配的内存
    if (Ehdr_count != 1) {
        perror("Error reading ELF header");
        free(ELFhdr);
        exit(EXIT_FAILURE);
    }
    return ELFhdr;
}

//创建指针数组 并存入数据
Elf64_Shdr* read_shdr(Elf64_Ehdr* ELFhdr,FILE* file) {
    Elf64_Shdr* ELFshdr;
    ELFshdr = (Elf64_Shdr *) malloc(ELFhdr->e_shnum * sizeof(Elf64_Shdr));//动态开辟一个可以存入 elf段表大小的空间 并返回指针数组
    //elf段表大小的空间 包含shnum个段的段表数据结构大小
    if (ELFshdr == NULL) {
        perror("Error opening ELF file");
        free(ELFshdr);
        free(ELFhdr);
        exit(EXIT_FAILURE);
    }

    //修改读写指针位置至段表偏移处
    if(fseek(file,(long)ELFhdr->e_shoff,SEEK_SET)){
        // 如果成功，fseek 返回0。
        // 如果失败，返回非零值。
        perror("fseek failed");
        free(ELFshdr);
        free(ELFhdr);
        exit(EXIT_FAILURE);
    }

    //将elf文件中的段表数据 存入shdr指向的指针数组
    size_t section_count = fread(ELFshdr, sizeof(Elf64_Shdr), ELFhdr->e_shnum, file);
    if (section_count != ELFhdr->e_shnum){
        perror("Error reading Section header");
        free(ELFshdr);
        free(ELFhdr);
        exit(EXIT_FAILURE);
    }
    return ELFshdr;
}

//输出ELF头文件中部分属性
void print_elf_detail(const Elf64_Ehdr *ELFhdr){
    if(ELFhdr == NULL){
        printf("Elf Header pointer is NULL.\n");
        return;
    }
    printf("\nELF Header:\n");
    printf("%4s%-30s","", "ELF type:");
    switch (ELFhdr->e_type) {
        case ET_NONE:
            printf( "No file type\n");
            break;
        case ET_REL:
            printf("Relocatable file\n");
            break;
        case ET_EXEC:
            printf("Executable file\n");
            break;
        case  ET_DYN:
            printf("Shared object file\n");
            break;
        case ET_CORE:
            printf("Core file\n");
            break;
        case ET_NUM:
            printf("Number of defined types\n");
            break;
        default:
            printf("Unknown type (%u)\n", ELFhdr->e_type);
            break;
    }
    //输出系统架构
    printf("%4s%-30s", " ","ELF machine:");
    switch(ELFhdr->e_machine){
        case EM_NONE:
            printf("No machine\n");
            break;
        case EM_386:
            printf("Intel 80386\n");
            break;
        case EM_X86_64:
            printf("AMD x86-64 architecture\n");
            break;
        case EM_SPARCV9:
            printf("SPARC v9 64-bit\n");
            break;
            // ... 添加更多case子句来处理其他机器类型
        default:
            printf("Unknown machine type (%u)\n", ELFhdr->e_machine);
            break;
    }
    //输出程序入口地址
    printf("%4s%-30s0x%lu\n", "","ELF entry:", ELFhdr->e_entry);
    //输出elf头的大小
    printf("%4s%-30s%hu\n", "","Size of this header:", ELFhdr->e_ehsize);
    //输出段表在elf文件中的偏移
    printf("%4s%-30s%lu(bytes into file)\n\n","", "Start of section headers:", ELFhdr->e_shoff);
}

//输出各个段表中部分属性
void print_section_detail(const Elf64_Shdr *ELFshdr,const Elf64_Ehdr *ELFhdr,FILE *file){
    //使用str_tab 指向动态分配的 大小为 段表字符串表的 地址空间
    char *str_tab = malloc(ELFshdr[ELFhdr->e_shstrndx].sh_size);
    //修改读写指针 将段表字符串表读入动态分配的内存中
    if(fseek(file,(long)ELFshdr[ELFhdr->e_shstrndx].sh_offset,SEEK_SET)){
        // fsekk函数返回值 如果成功， 返回0。如果失败，返回非零值。
        perror("fseek failed");
        free(str_tab);
        exit(EXIT_FAILURE);
    }

    size_t shstr_num = fread(str_tab,ELFshdr[ELFhdr->e_shstrndx].sh_size,1,file);
    if ( shstr_num != 1) {
        perror("Error reading ELF header");
        free(str_tab);
        exit(EXIT_FAILURE);
    }

    printf("Section Headers:\n");
    printf("    %-8s%-20s%-15s%-15s%-15s%-15s\n","[NR]","sh_name:","sh_offset:","sh_size:","sh_type:","type_name");

    for(int i=0;i<ELFhdr->e_shnum;i++){
        //使用指针 指向段表字符串表中的 该段的下标
        const char *s_name = str_tab+ ELFshdr[i].sh_name;
        //打印输出各个段的名字、文件偏移、大小、类型
        printf("    [%2d]    %-20s%-15lu%-15lu%-15u",i,s_name,ELFshdr[i].sh_offset,ELFshdr[i].sh_size,ELFshdr[i].sh_type);

        // 使用switch-case结构来打印sh_type
        switch (ELFshdr[i].sh_type) {
            case SHT_NULL:
                printf("%-15s\n", "Unused section");
                break;
            case SHT_PROGBITS:
                printf("%-15s\n", "Program data");
                break;
            case SHT_SYMTAB:
                printf("%-15s\n", "Symbol table");
                break;
            case SHT_STRTAB:
                printf("%-15s\n", "String table");
                break;
            case SHT_RELA:
                printf("%-15s\n", "Relocation with addends");
                break;
            case SHT_HASH:
                printf("%-15s\n", "Symbol hash table");
                break;
            case SHT_DYNAMIC:
                printf("%-15s\n", "Dynamic linking info");
                break;
            case SHT_NOTE:
                printf("%-15s\n", "Notes");
                break;
            case SHT_NOBITS:
                printf("%-15s\n", "BSS (no data)");
                break;
            case SHT_REL:
                printf("%-15s\n", "Relocation entries");
                break;
            case SHT_DYNSYM:
                printf("%-15s\n", "Dynamic linker symbol table");
                break;
            case SHT_INIT_ARRAY:
                printf("%-15s\n", "Constructors array");
                break;
            case SHT_FINI_ARRAY:
                printf("%-15s\n", "Destructors array");
                break;
            case SHT_PREINIT_ARRAY:
                printf("%-15s\n", "Pre-constructors array");
                break;
            case SHT_GROUP:
                printf("%-15s\n", "Section group");
                break;
            case SHT_SYMTAB_SHNDX:
                printf("%-15s\n", "Extended section indices");
                break;
            default:
                printf("%-15s\n", "Unknown type");
                break;
        }
    }
    free(str_tab);
}


//输出符号表细节
void print_symtab_detail (const Elf64_Shdr *ELFshdr,const Elf64_Ehdr *ELFhdr,FILE *file){
    //得到 段表字符串表 在段表中的下标
    int shstrtab_index =ELFhdr->e_shstrndx;

    //读入段表字符串表
    char *shstr_tab =malloc(ELFshdr[shstrtab_index].sh_size);
    if(fseek(file,(long )ELFshdr[shstrtab_index].sh_offset,SEEK_SET)){
        perror("fseek failed");
        free(shstr_tab);
        exit(EXIT_FAILURE);
    }
    size_t shstr_num = fread(shstr_tab,ELFshdr[shstrtab_index].sh_size,1,file);
    if (shstr_num != 1) {
        perror("Error reading ELF header");
        free(shstr_tab);
        exit(EXIT_FAILURE);
    }

    //通过段名判断 符号表段 和 字符串段 在段表中的下标
    int symtab_index = -1, strtab_index = -1;
    for(int i=0;i<ELFhdr->e_shnum;i++){

        const char *s_name =shstr_tab + ELFshdr[i].sh_name;

        //使用strcmp函数进行比较 来获取下标
        if (strcmp(s_name, ".symtab") == 0) {
            symtab_index = i;
        }
        else if (strcmp(s_name, ".strtab") == 0) {
            strtab_index = i;
        }
    }

    if (symtab_index == -1 || strtab_index == -1) {
        fprintf(stderr, "Symbol table or string table not found\n");
        free(shstr_tab);
        exit(EXIT_FAILURE);
    }

    //修改读写指针读入符号表 并且使用ELF_symbols 记录每个符号数据结构的指针数组
    if (fseek(file,(long)ELFshdr[symtab_index].sh_offset,SEEK_SET)){
        // fsekk函数返回值 如果成功， 返回0。如果失败，返回非零值。
        free(shstr_tab);
        perror("fseek failed");
        exit(EXIT_FAILURE);
    }
    Elf64_Sym *ELF_symbols = malloc(ELFshdr[symtab_index].sh_size);
    size_t symbol_count = fread(ELF_symbols,ELFshdr[symtab_index].sh_entsize,ELFshdr[symtab_index].sh_size/ELFshdr[symtab_index].sh_entsize,file);
    if (symbol_count != ELFshdr[symtab_index].sh_size/ELFshdr[symtab_index].sh_entsize) {
        perror("Error reading ELF_symbols");
        free(ELF_symbols);
        exit(EXIT_FAILURE);
    }

    //根据字符串表在段表中的下标读入字符串表 用malloc分配字符串 来接受
    char *str_tab =malloc(ELFshdr[strtab_index].sh_size);
    if(fseek(file,(long )ELFshdr[strtab_index].sh_offset,SEEK_SET)){
        perror("fseek failed");
        free(str_tab);
        free(ELF_symbols);
        exit(EXIT_FAILURE);
    }
    size_t str_num = fread(str_tab,ELFshdr[strtab_index].sh_size,1,file);
    if (str_num != 1) {
        perror("Error reading ELF header");
        free(str_tab);
        free(ELF_symbols);
        exit(EXIT_FAILURE);
    }

    //输出表头信息
    printf("\n\nSymbol table '.symtab' contains %lu entries:\n", ELFshdr[symtab_index].sh_size / ELFshdr[symtab_index].sh_entsize);
    printf("   Num:    Value            Size  Bind       Vis      Ndx    Name\n");

    //循环输出字符表中每一行的细节信息
    for (int j = 0; j < ELFshdr[symtab_index].sh_size / ELFshdr[symtab_index].sh_entsize; j++) {
        Elf64_Sym *sym = &ELF_symbols[j];
        //从字符串表中读入字符名称
        const char *name = str_tab + sym->st_name;
        // 输出符号信息
        printf("%5d  0x%016lx %6lu ", j, sym->st_value, sym->st_size);

        // 输出绑定信息
         switch (ELF64_ST_TYPE(sym->st_info)) {
             case STT_NOTYPE:  printf(" NOTYPE "); break;
             case STT_OBJECT:  printf(" OBJECT "); break;
             case STT_FUNC:    printf(" FUNC   "); break;
             case STT_SECTION: printf(" SECTION"); break;
             case STT_FILE:    printf(" FILE   "); break;
             case STT_COMMON:  printf(" COMMON "); break;
             case STT_TLS:     printf(" TLS    "); break;
             default:          printf(" UNKNOWN"); break;
         }

         // 输出可见性
         switch (ELF64_ST_VISIBILITY(sym->st_other)) {
               case STV_DEFAULT:   printf("  DEFAULT  "); break;
               case STV_PROTECTED: printf("  PROTECTED"); break;
               case STV_HIDDEN:    printf("  HIDDEN   "); break;
               case STV_INTERNAL:  printf("  INTERNAL "); break;
               default:            printf("  UNKNOWN  "); break;
         }

         //输出符号所在的段号
         if (sym->st_shndx == SHN_UNDEF) {
             printf("  UND ");
         } else if (sym->st_shndx == SHN_ABS) {
             printf("  ABS ");
         } else
              printf("%5d ", sym->st_shndx);

         //输出符号或者段名称
        if(ELF64_ST_TYPE(sym->st_info)==STT_SECTION){
           const char *s_name =shstr_tab + ELFshdr[sym->st_shndx].sh_name;
           printf("  %-15s\n",  s_name);
        }else
            printf("  %-15s\n",  name);
    }
    free(str_tab);
    free(shstr_tab);
    free(ELF_symbols);
}

void symbol_revise(const Elf64_Shdr *ELFshdr,const Elf64_Ehdr *ELFhdr,FILE *file){
    //得到 段表字符串表 在段表中的下标
    int shstrtab_index =ELFhdr->e_shstrndx;

    //读入段表字符串表
    char *shstr_tab =malloc(ELFshdr[shstrtab_index].sh_size);
    if(fseek(file,(long )ELFshdr[shstrtab_index].sh_offset,SEEK_SET)){
        perror("fseek failed");
        free(shstr_tab);
        exit(EXIT_FAILURE);
    }
    size_t shstr_num = fread(shstr_tab,ELFshdr[shstrtab_index].sh_size,1,file);
    if (shstr_num != 1) {
        perror("Error reading ELF header");
        free(shstr_tab);
        exit(EXIT_FAILURE);
    }

    //通过段名判断 符号表段和打他段  和在段表中的下标
    int symtab_index = -1 , data_index= -1;
    for(int i=0;i<ELFhdr->e_shnum;i++){
        const char *s_name =shstr_tab + ELFshdr[i].sh_name;
        //使用strcmp函数 比较字符串获取下标
        if (strcmp(s_name, ".symtab") == 0) {
            symtab_index = i;
        }
        else if(strcmp(s_name, ".data") == 0) {
            data_index = i;
        }
    }
    if (symtab_index == -1 ||data_index == -1) {
        fprintf(stderr, "Symbol table or data not found\n");
        free(shstr_tab);
        exit(EXIT_FAILURE);
    }

    //修改读写指针 读入符号表 并且使用ELF_symbols 记录每个符号数据结构的指针数组
    if (fseek(file,(long)ELFshdr[symtab_index].sh_offset,SEEK_SET)){
        // fsekk函数返回值 如果成功， 返回0。如果失败，返回非零值。
        perror("fseek failed");
        exit(EXIT_FAILURE);
    }
    Elf64_Sym *ELF_symbols = malloc(ELFshdr[symtab_index].sh_size);
    size_t symbol_count = fread(ELF_symbols,ELFshdr[symtab_index].sh_entsize,ELFshdr[symtab_index].sh_size/ELFshdr[symtab_index].sh_entsize,file);
    if (symbol_count != ELFshdr[symtab_index].sh_size/ELFshdr[symtab_index].sh_entsize) {
        perror("Error reading ELF_symbols");
        free(ELF_symbols);
        exit(EXIT_FAILURE);
    }

    //找到要修改的符号
    char *new_var ="hello world";
    size_t new_var_len = strlen(new_var);
    for (int k = 0; k < ELFshdr[symtab_index].sh_size / ELFshdr[symtab_index].sh_entsize; k++){
       if(ELF64_ST_TYPE(ELF_symbols[k].st_info) == STT_OBJECT && ELF_symbols[k].st_size != 0 && ELF_symbols[k].st_shndx==data_index && ELF_symbols[k].st_size != 8){

           if(new_var_len >ELF_symbols[k].st_size ){
               perror("Var size is too large");
               free(ELF_symbols);
               exit(EXIT_FAILURE);
           }
            //在可重定位文件和可执行文件中 符号表中st.value 代表的含义不一样 可重定位文件代表 该符号在data段中的偏移
            // 而在可重定位文件则代表虚拟地址 其在ELF文件中的偏移需要 ELF_symbols[k].st_value-ELFshdr[data_index].sh_addr
           fseek(file, (long)(ELFshdr[data_index].sh_offset + ELF_symbols[k].st_value), SEEK_SET);
           if (ferror(file)) {
               perror("fseek failed");
               free(ELF_symbols);
               free(shstr_tab);
               fclose(file);
               exit(EXIT_FAILURE);
           }
           // 写入新字符串
           size_t written = fwrite(new_var, 1, new_var_len, file);
           if (written != new_var_len) {
               perror("Error writing to file");
               free(ELF_symbols);
               free(shstr_tab);
               fclose(file);
               exit(EXIT_FAILURE);
           }
       }
       else if(ELF64_ST_TYPE(ELF_symbols[k].st_info) == STT_OBJECT && ELF_symbols[k].st_size == 8 && ELF_symbols[k].st_shndx==data_index ){
           fseek(file, (long)(ELFshdr[data_index].sh_offset + ELF_symbols[k].st_value), SEEK_SET);
           if (ferror(file)) {
               perror("fseek failed while seeking to symbol's pointer");
               free(ELF_symbols);
               free(shstr_tab);
               exit(EXIT_FAILURE);
           }

           long new_adr;
           if (fread(&new_adr, sizeof(long), 1, file) != 1) {
               perror("Error reading pointer value from file");
               free(ELF_symbols);
               free(shstr_tab);
               exit(EXIT_FAILURE);
           }

           // 现在，我们有了指针指向的地址，尝试移动到那个地址
           fseek(file, (long)new_adr, SEEK_SET);
           if (ferror(file)) {
               perror("fseek failed while seeking to pointer's target address");
               free(ELF_symbols);
               free(shstr_tab);
               exit(EXIT_FAILURE);
           }

           // 写入新字符串
           size_t written = fwrite(new_var, 1, new_var_len + 1, file); // 注意：这里+1是为了包含字符串终止符
           if (written != new_var_len + 1) {
               perror("Error writing to file at pointer's target address");
               free(ELF_symbols);
               free(shstr_tab);
               exit(EXIT_FAILURE);
           }
       }
    }
}
