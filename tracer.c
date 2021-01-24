#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <elf.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/user.h>

//#define DEBUG

#define N 100
#define INT_3 0xCC

int bp = 0;
typedef struct breakpoint{
	size_t addr;
	char name[25];
	size_t orig_code;
}Breakpoint;
Breakpoint bp_list[N];

int extract_ELF_format(char *file){
	Elf64_Ehdr header;
	Elf64_Shdr section_header; 
    	FILE *fp = fopen(file,"r");
    	if(!fp){
        	perror("open failed");
        	exit(-1);
    	}
	
	fread(&header, sizeof(Elf64_Ehdr), 1, fp);	//read elf header of target file
	//printf("[%s]Entry is: 0x%llx\n",file,header.e_entry);	//_start 
	//printf("[%s]Start of section header: 0x%llx\n",file,header.e_shoff);
	//printf("[%s]Number of sections: 0x%llx\n",file,header.e_shnum);
	fseek(fp, header.e_shoff, SEEK_SET);		//move the pointer to Section Header Table		
	printf("\n");
	for(int i=0;i < header.e_shnum;i++){
	/* scan section header */
		fread(&section_header, sizeof(Elf64_Shdr), 1, fp); 
		//if(section_header.sh_type != SHT_NULL){printf("sh_link:%d\n",section_header.sh_link);}
		if(section_header.sh_type == SHT_SYMTAB){	// if this section is symbol table?
			// now section_header represents Elf Symbol Table.
			//printf("Symbol table addr:0x%llx\n",section_header.sh_offset);
			Elf64_Shdr str_section_header;
			int sym_entry_count=0;
			size_t str_table_offset = header.e_shoff + section_header.sh_link * sizeof(Elf64_Shdr);		// section_header.sh_link 输出为 30，也就是symbol table在段表中的索引。
			fseek(fp,str_table_offset,SEEK_SET);					//定位到字符串表
			fread(&str_section_header, sizeof(Elf64_Shdr), 1, fp);	//读取字符串表表头 
			
			fseek(fp,section_header.sh_offset,SEEK_SET);			//定位到符号表表头
			sym_entry_count = section_header.sh_size/section_header.sh_entsize;
			//printf("[*] %d entries in symbol table\n",sym_entry_count);

			
			for(int i=0;i<sym_entry_count; i++){
				//符号表中每一个元素是一个 Elf64_Sym
				Elf64_Sym sym;
				fread(&sym, sizeof(Elf64_Sym), 1,fp);				//每次读一个Symbol
				if(ELF64_ST_TYPE(sym.st_info) == STT_FUNC && sym.st_name!=0 && sym.st_value != 0){
					/* 如果该符号是一个函数或其他可执行代码，在字符串表中，且虚拟地址不为0 */
					long file_ops = ftell(fp);										//保存此时fp的位置
					fseek(fp,str_section_header.sh_offset+sym.st_name,SEEK_SET);	//定位到字符串表中对应符号的位置
					bp_list[bp].addr = sym.st_value;
					fread(bp_list[bp].name,25,sizeof(char),fp);						//读取对应的符号
					bp = bp + 1;
					fseek(fp,file_ops,SEEK_SET);									//恢复fp到上一次读取的Symbol的位置，准备下一次读取。
				}
			}
		}
	}
}

int breakpoint_injection(pid_t child){
	/* 我们向每个函数的第一条指令的位置注入INT 3 即 0xCC  */
	for(int i=0 ; i<bp ; i++){
		//使用ptrace读出一个字节存在orgi code中
		bp_list[i].orig_code = ptrace(PTRACE_PEEKTEXT,child,bp_list[i].addr,0);

		#ifdef DEBUG
		printf("[*] Set Breakpoint:0x%llx,0x%llx\n",bp_list[i].addr,bp_list[i].orig_code);
		#endif

		ptrace(PTRACE_POKETEXT, child, bp_list[i].addr, (bp_list[i].orig_code & 0xFFFFFFFFFFFFFF00) | INT_3);	//将最低为的字节打入 int 3
	}

	printf("\n");

	#ifdef DEBUG
	check_bp(child);
	#endif


}

void show_bp(){
	for(int i=0;i<bp;i++){
		printf("[*] Set Breakpoint:0x%llx,0x%llx\n",bp_list[i].addr,bp_list[i].orig_code);
	}
}

void check_bp(pid_t child){
	for(int i=0;i<bp;i++)
	{
		printf("[*] Check Breakpoint:0x%llx,0x%llx\n",bp_list[i].addr,ptrace(PTRACE_PEEKTEXT,child,(void *)bp_list[i].addr,0));
	}
}

int if_bp_hit(struct user_regs_struct regs)
{
			for(int i=0;i<bp;i++)
			{
				if(bp_list[i].addr==(regs.rip-1))
				{
					#ifdef DEBUG
					printf("Hit Breakpoint: 0x%llx\n",bp_list[i].addr);
					#endif
					return i;
				}
			}
			return -1;
}
int main(int argc, char **argv){
    pid_t child;
	int status;
	int hit_index;
	struct user_regs_struct regs;
    if(argc<2){
        printf("Plz input the file you wanna trace :-)\n");
        exit(0);
    }
	child = fork();

	if(child == 0){
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		execl(argv[1],argv[1],NULL);
		perror("fail exec");
		exit(-1);
	}
	else{
		printf("[+] Tracing PID:%d\n",child);
		extract_ELF_format(argv[1]);
		wait(NULL); 						//等待子进程的exec
		breakpoint_injection(child);		//INT 3注入
		//show_bp();
		ptrace(PTRACE_CONT,child,0,0);
		puts("[+] Start");
		while(1){
			//puts(1);
			waitpid(child,&status,0);		//等待子进程的信号
			
			/* 捕获信号之后判断信号类型	*/
			if(WIFEXITED(status)){
				/* 如果是EXit信号 */
				printf("\n[+] Child process EXITED!\n");
				return 0;
			}
			if(WIFSTOPPED(status))
			{
				/* 如果是STOP信号 */
				if(WSTOPSIG(status)==SIGTRAP)
				{				//如果是触发了SIGTRAP,说明碰到了断点
					ptrace(PTRACE_GETREGS,child,0,&regs);	//读取此时用户态寄存器的值，准备为回退做准备
					//printf("[+] SIGTRAP rip:0x%llx\n",regs.rip);
					/* 将此时的addr与我们bp_list中维护的addr做对比，如果查找到，说明断点命中 */
					if((hit_index=if_bp_hit(regs))==-1)
					{
						/*未命中*/
						printf("MISS, fail to hit:0x%llx\n",regs.rip);
						exit(-1);
					}
					else
					{
						/*如果命中*/
						/*输出命中信息*/
						printf("%s()\n",bp_list[hit_index].name);
						/*把INT 3 patch 回本来正常的指令*/
						ptrace(PTRACE_POKETEXT,child,bp_list[hit_index].addr,bp_list[hit_index].orig_code);
						/*执行流回退，重新执行正确的指令*/
						regs.rip = bp_list[hit_index].addr;
						ptrace(PTRACE_SETREGS,child,0,&regs);

						/*单步执行一次，然后恢复断点*/
						ptrace(PTRACE_SINGLESTEP,child,0,0);
						wait(NULL);
						/*恢复断点*/
						ptrace(PTRACE_POKETEXT, child, bp_list[hit_index].addr, (bp_list[hit_index].orig_code & 0xFFFFFFFFFFFFFF00) | INT_3);
					}
				}	
			}
			ptrace(PTRACE_CONT,child,0,0);
		}
	}
    return 0;
}


