#include <stdio.h>
#include <stdlib.h>
#include <sys/user.h>
#include <asm/ptrace.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <android/log.h>
#include <errno.h>
#include <string.h>

#if defined(__x86_64__)
#define pt_regs         user_regs_struct
#endif

#define ENABLE_DEBUG 1

#if ENABLE_DEBUG
#define  LOG_TAG "INJECT"
#define  LOGD(fmt, args...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG, fmt, ##args)
#define DEBUG_PRINT(format,args...) \
    LOGD(format, ##args)
#else
#define DEBUG_PRINT(format,args...)
#endif

#define CPSR_T_MASK     ( 1u << 5 )

#if defined(__x86_64__)
const char *libc_path = "/system/lib64/libc.so";
const char *linker_path = "/system/bin/linker64";
#else
const char *libc_path = "/system/lib/libc.so";
const char *linker_path = "/system/bin/linker";
#endif

int ptrace_readdata(pid_t pid,  uint8_t *src, uint8_t *buf, size_t size)
{
    uint64_t i, j, remain;
    uint8_t *laddr;
    int length=sizeof(long);
    union u {
        long val;
        char chars[8];
    } d;

    j = size / length;
    remain = size % length;

    laddr = buf;
    //printf("length: %d %d\n",j,remain);
    for (i = 0; i < j; i ++) {
        d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);
        //printf("d:%s\n",d.chars);
        memcpy(laddr, d.chars, length);
        src += length;
        laddr += length;
    }

    if (remain > 0) {
        d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);
        memcpy(laddr, d.chars, remain);
    }

    return 0;
}

int ptrace_writedata(pid_t pid, uint8_t *dest, uint8_t *data, size_t size)
{

    uint64_t i, j, remain;
    uint8_t *laddr;
    int length= sizeof(long);
    union u {
        long val;
        char chars[8];
    } d;

    j = size / length;
    remain = size % length;

    laddr = data;

    for (i = 0; i < j; i ++) {
        memcpy(d.chars, laddr, length);
        //printf("write d:%s %llx\n",d.chars,laddr);
        ptrace(PTRACE_POKETEXT, pid, dest, d.val);
        dest  += length;
        laddr += length;
    }

    if (remain > 0) {
        d.val = ptrace(PTRACE_PEEKTEXT, pid, dest, 0);
        for (i = 0; i < remain; i ++) {
            d.chars[i] = *laddr ++;
        }

        ptrace(PTRACE_POKETEXT, pid, dest, d.val);
    }

    return 0;
}

#if defined(__arm__)
int ptrace_call(pid_t pid, uint64_t addr, long *params, uint64_t num_params, struct pt_regs* regs)
{
    uint64_t i;
    for (i = 0; i < num_params && i < 4; i ++) {
        regs->uregs[i] = params[i];
    }
    //
    // push remained params onto stack
    //
    if (i < num_params) {
        regs->ARM_sp -= (num_params - i) * sizeof(long) ;
        ptrace_writedata(pid, (void *)regs->ARM_sp, (uint8_t *)&params[i], (num_params - i) * sizeof(long));
    }

    regs->ARM_pc = addr;
    if (regs->ARM_pc & 1) {
        /* thumb */
        regs->ARM_pc &= (~1u);
        regs->ARM_cpsr |= CPSR_T_MASK;
    } else {
        /* arm */
        regs->ARM_cpsr &= ~CPSR_T_MASK;
    }

    regs->ARM_lr = 0;

    if (ptrace_setregs(pid, regs) == -1
            || ptrace_continue(pid) == -1) {
        printf("error\n");
        return -1;
    }

    int stat = 0;
    waitpid(pid, &stat, WUNTRACED);
    while (stat != 0xb7f) {
        if (ptrace_continue(pid) == -1) {
            printf("error\n");
            return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }

    return 0;
}

#elif defined(__x86_64__)
long ptrace_call(pid_t pid, uint64_t addr, long *params, uint64_t num_params, struct user_regs_struct * regs)
{
    struct user_regs_struct regs_ori;
    //memcpy(regs, regs_ori, sizeof(regs_ori));

    ptrace_getregs(pid,&regs_ori);
    memcpy(regs, &regs_ori, sizeof(regs_ori));

    uint64_t i;
    for(i=0;i<num_params&&i<6;i++){
        if(i==0)regs->rdi=params[i];
        if(i==1)regs->rsi=params[i];
        if(i==2)regs->rdx=params[i];
        if(i==3)regs->rcx=params[i];
        if(i==4)regs->r8=params[i];
        if(i==5)regs->r9=params[i];
    }
    if(i<num_params){
        //超过6个参数时用栈传递
        regs->rsp -= (num_params - i) * sizeof(long) ;
        ptrace_writedata(pid, (void *)regs->rsp, (uint8_t *)&params[i], (num_params - i) * sizeof(long));
    }


    long tmp_addr = 0x00;
    if(regs->rsp%16!=0) //重要！栈对齐
        regs->rsp -= sizeof(long);
    regs->rsp -= sizeof(long);
    ptrace_writedata(pid, regs->rsp, (char *)&tmp_addr, sizeof(tmp_addr));
    regs->rax=0;
    regs->rip = addr;

    printf("regs->rsp: %llx\n",regs->rsp);

    if (ptrace_setregs(pid, regs) == -1
            || ptrace_continue(pid) == -1) {
        printf("error\n");
        return -1;
    }

   // printf("errno=%d\n",errno);

    int stat = 0;
    waitpid(pid, &stat, WUNTRACED);
//    while (stat != 0xb7f) {
//        if (ptrace_continue(pid) == -1) {
//            printf("error\n");
//            return -1;
//        }
//        waitpid(pid, &stat, WUNTRACED);
//    }

    return 0;
}
#else
#error "Not supported"
#endif


int ptrace_getregs(pid_t pid, struct pt_regs * regs)
{

#if defined (__x86_64__)
    int regset = NT_PRSTATUS;
		struct iovec ioVec;

		ioVec.iov_base = regs;
		ioVec.iov_len = sizeof(*regs);
    if (ptrace(PTRACE_GETREGSET, pid, (void*)regset, &ioVec) < 0) {
        perror("ptrace_getregs: Can not get register values");
        printf(" io %llx, %d", ioVec.iov_base, ioVec.iov_len);
        return -1;
    }

    return 0;
#else
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
        perror("ptrace_getregs: Can not get register values");
        return -1;
    }

    return 0;
#endif
}

int ptrace_setregs(pid_t pid, struct pt_regs * regs)
{

#if defined (__x86_64__)
    int regset = NT_PRSTATUS;
		struct iovec ioVec;

		ioVec.iov_base = regs;
		ioVec.iov_len = sizeof(*regs);
    if (ptrace(PTRACE_SETREGSET, pid, (void*)regset, &ioVec) < 0) {
        perror("ptrace_setregs: Can not get register values");
        return -1;
    }

    return 0;
#else
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
        perror("ptrace_setregs: Can not set register values");
        return -1;
    }

    return 0;
#endif
}


int ptrace_continue(pid_t pid)
{
    if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
        perror("ptrace_cont");
        return -1;
    }

    return 0;
}

int ptrace_attach(pid_t pid)
{
    if (ptrace(PTRACE_ATTACH, pid, NULL, 0) < 0) {
        perror("ptrace_attach");
        return -1;
    }

    int status = 0;
    waitpid(pid, &status , WUNTRACED);

    return 0;
}

int ptrace_detach(pid_t pid)
{
    if (ptrace(PTRACE_DETACH, pid, NULL, 0) < 0) {
        perror("ptrace_detach");
        return -1;
    }

    return 0;
}

void* get_module_base(pid_t pid, const char* module_name)
{
    FILE *fp;
    long addr = 0;
    char *pch;
    char filename[64];
    char line[1024];

    if (pid < 0) {
        /* self process */
        snprintf(filename, sizeof(filename), "/proc/self/maps", pid);
    } else {
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }

    fp = fopen(filename, "r");

    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, module_name)) {
                pch = strtok( line, "-" );
                addr = strtoul( pch, NULL, 16 );

                if (addr == 0x8000)
                    addr = 0;

                break;
            }
        }

        fclose(fp) ;
    }

    return (void *)addr;
}

void* get_remote_addr(pid_t target_pid, const char* module_name, void* local_addr)
{
    void* local_handle, *remote_handle;

    local_handle = get_module_base(-1, module_name);
    remote_handle = get_module_base(target_pid, module_name);

    DEBUG_PRINT("[+] get_remote_addr: local[%llx], remote[%llx]\n", local_handle, remote_handle);

    void * ret_addr = (void *)((uint64_t)local_addr + (uint64_t)remote_handle - (uint64_t)local_handle);

#if defined(__x86_64__)
//    if (!strcmp(module_name, libc_path)) {
//        //ret_addr += 2;
//        printf("comp: %s %s\n",module_name,libc_path);
//
//    }
//    if ((module_name!=libc_path)) {
//        //ret_addr += 4;
//        printf("comp2: %s %s\n",module_name,libc_path);
//    }
#endif
    return ret_addr;
}

int find_pid_of(const char *process_name)
{
    int id;
    pid_t pid = -1;
    DIR* dir;
    FILE *fp;
    char filename[64];
    char cmdline[256];

    struct dirent * entry;

    if (process_name == NULL)
        return -1;

    dir = opendir("/proc");
    if (dir == NULL)
        return -1;

    while((entry = readdir(dir)) != NULL) {
        id = atoi(entry->d_name);
        if (id != 0) {
            sprintf(filename, "/proc/%d/cmdline", id);
            fp = fopen(filename, "r");
            if (fp) {
                fgets(cmdline, sizeof(cmdline), fp);
                fclose(fp);

                if (strcmp(process_name, cmdline) == 0) {
                    /* process found */
                    pid = id;
                    break;
                }
            }
        }
    }

    closedir(dir);
    return pid;
}

long ptrace_retval(struct pt_regs * regs)
{
#if defined(__arm__)
    return regs->ARM_r0;
#elif defined(__x86_64__)
    return regs->rax;
#else
#error "Not supported"
#endif
}

long ptrace_ip(struct pt_regs * regs)
{
#if defined(__arm__)
    return regs->ARM_pc;
#elif defined(__x86_64__)
    return regs->rip;
#else
#error "Not supported"
#endif
}

int ptrace_call_wrapper(pid_t target_pid, const char * func_name, void * func_addr, long * parameters, int param_num, struct pt_regs * regs)
{
    DEBUG_PRINT("[+] Calling %s in target process.\n", func_name);
    if (ptrace_call(target_pid, (uint64_t)func_addr, parameters, param_num, regs) == -1)
        return -1;

    if (ptrace_getregs(target_pid, regs) == -1)
        return -1;
//    for(int i=0;i<4;i++){
//        if(ptrace_ip(regs)!=0){
//            ptrace_call_wrapper(target_pid,func_name, void * func_addr, long * parameters, int param_num, struct pt_regs * regs);
//        }
//    }
    DEBUG_PRINT("[+] Target process returned from %s, return value=%llx, pc=%llx ,rsp:%llx\n",
                func_name, ptrace_retval(regs), ptrace_ip(regs),regs->rsp);

    return 0;
}

int inject_remote_process(pid_t target_pid, const char *library_path, const char *function_name, const char *param, size_t param_size)
{
    int ret = -1;
    void *mmap_addr, *dlopen_addr, *dlsym_addr, *dlclose_addr, *dlerror_addr;
    void *local_handle, *remote_handle, *dlhandle;
    uint8_t *map_base = 0;
    uint8_t *dlopen_param1_ptr, *dlsym_param2_ptr, *saved_r0_pc_ptr, *inject_param_ptr, *remote_code_ptr, *local_code_ptr;

    struct pt_regs regs, original_regs;
    extern uint64_t _dlopen_addr_s, _dlopen_param1_s, _dlopen_param2_s, _dlsym_addr_s, \
        _dlsym_param2_s, _dlclose_addr_s, _inject_start_s, _inject_end_s, _inject_function_param_s, \
        _saved_cpsr_s, _saved_r0_pc_s;

    uint64_t code_length;
    long parameters[10];

    DEBUG_PRINT("[+] Injecting process: %d\n", target_pid);

    if (ptrace_attach(target_pid) == -1)
        goto exit;

    if (ptrace_getregs(target_pid, &regs) == -1)
        goto exit;

    /* save original registers */
    memcpy(&original_regs, &regs, sizeof(regs));

    printf("local mmap: %llx\n",(void *)mmap);
    mmap_addr = get_remote_addr(target_pid, libc_path, (void *)mmap);

    dlopen_addr = get_remote_addr( target_pid, linker_path, (void *)dlopen );
    dlsym_addr = get_remote_addr( target_pid, linker_path, (void *)dlsym );
    dlclose_addr = get_remote_addr( target_pid, linker_path, (void *)dlclose );
    dlerror_addr = get_remote_addr( target_pid, linker_path, (void *)dlerror );

    DEBUG_PRINT("[+] Remote mmap address: %llx\n", mmap_addr);

    /* call mmap */
    parameters[0] = 0;  // addr
    parameters[1] = 0x4000; // size
    parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot
    parameters[3] = MAP_ANONYMOUS | MAP_PRIVATE; // flags
    parameters[4] = 0; //fd
    parameters[5] = 0; //offset


    if (ptrace_call_wrapper(target_pid, "mmap", mmap_addr, parameters, 6, &regs) == -1)
        goto exit;

    map_base = ptrace_retval(&regs);

    if (ptrace_call_wrapper(target_pid, "dlerror", dlerror_addr, parameters, 0, &regs) == -1)
        goto exit;
    char ttp[100];
    ptrace_readdata(target_pid, ptrace_retval(&regs), ttp, strlen(library_path) + 1);
    printf("error0 :%s\n",ttp);
    //printf("error0: %s\n",ptrace_retval(&regs));


    DEBUG_PRINT("[+] Get imports: dlopen: %llx, dlsym: %llx, dlclose: %llx, dlerror: %llx\n",
                dlopen_addr, dlsym_addr, dlclose_addr, dlerror_addr);

    printf("library path = %s\n", library_path);


    ptrace_writedata(target_pid, map_base, library_path, strlen(library_path) + 1);

    //char ttp[100];
    ptrace_readdata(target_pid, map_base, ttp, strlen(library_path) + 1);
    printf("rd:%s\n",ttp);

    parameters[0] = map_base;
    parameters[1] = RTLD_NOW | RTLD_GLOBAL;

    if (ptrace_call_wrapper(target_pid, "dlopen", dlopen_addr, parameters, 2, &regs) == -1)
        goto exit;
    void * sohandle = ptrace_retval(&regs);

    if (ptrace_call_wrapper(target_pid, "dlerror", dlerror_addr, parameters, 0, &regs) == -1)
        goto exit;
    //char ttp[100];
    ptrace_readdata(target_pid, ptrace_retval(&regs), ttp, strlen(library_path) + 1);
    printf("error :%s\n",ttp);


#define FUNCTION_NAME_ADDR_OFFSET       0x100
    ptrace_writedata(target_pid, map_base + FUNCTION_NAME_ADDR_OFFSET, function_name, strlen(function_name) + 1);
    parameters[0] = sohandle;
    parameters[1] = map_base + FUNCTION_NAME_ADDR_OFFSET;

    if (ptrace_call_wrapper(target_pid, "dlsym", dlsym_addr, parameters, 2, &regs) == -1)
        goto exit;

    void * hook_entry_addr = ptrace_retval(&regs);
    DEBUG_PRINT("hook_entry_addr = %p\n", hook_entry_addr);

#define FUNCTION_PARAM_ADDR_OFFSET      0x200
    ptrace_writedata(target_pid, map_base + FUNCTION_PARAM_ADDR_OFFSET, param, strlen(param) + 1);
    parameters[0] = map_base + FUNCTION_PARAM_ADDR_OFFSET;

    if (ptrace_call_wrapper(target_pid, "hook_entry", hook_entry_addr, parameters, 1, &regs) == -1)
        goto exit;

    printf("Press enter to dlclose and detach\n");
    getchar();
    parameters[0] = sohandle;

    if (ptrace_call_wrapper(target_pid, "dlclose", dlclose, parameters, 1, &regs) == -1)
        goto exit;

    /* restore */
    ptrace_setregs(target_pid, &original_regs);
    ptrace_detach(target_pid);
    ret = 0;

    exit:
    return ret;
}

int main(int argc, char** argv) {
    pid_t target_pid;
    if(argc>2){
        printf("Can't support arguments\n");
        return -1;
    }
    if(argc==1)
        target_pid = find_pid_of("/system/bin/surfaceflinger");
    else{
        target_pid = find_pid_of(argv[1]);
    }
    if (-1 == target_pid) {
        printf("Can't find the process\n");
        return -1;
    }
    //printf("target pid= %d\n",target_pid);
    inject_remote_process(target_pid, "/data/libhello.so", "hook_entry",  "I'm parameter!", strlen("I'm parameter!"));
    return 0;
}  