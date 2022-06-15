#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <android/log.h>
#include <EGL/egl.h>
#include <GLES/gl.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
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
#include <time.h>

#define LOG_TAG "DEBUG"
#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)

//todo:寻找比设置全局变量更安全的方式
int minu=-1;
int cnt=0;
long ids[100];
int times[100]={0};

EGLBoolean (*old_eglSwapBuffers)(EGLDisplay dpy, EGLSurface surf) = -1;


//在我们hook进去的代码里，首先进行帧率检测，再调用原始的eglSwapBuffers
EGLBoolean new_eglSwapBuffers(EGLDisplay dpy, EGLSurface surface)
{
    if(minu==-1){
        time_t now;
        struct tm *timeNow;
        time(&now);
        timeNow = localtime(&now);
        minu=timeNow->tm_min;
    }
    int id=0;
    long curId=surface;
    for(int i=1;i<=cnt;i++){
        if(ids[i]==curId){
            id=i;break;
        }
    }
    if(id==0){
        ids[++cnt]=curId;
        id=cnt;
        times[cnt]=0;
    }
    time_t now;
    struct tm *timeNow;
    time(&now);
    timeNow = localtime(&now);
    //参数设置可更改，目前是五分钟。todo：将设置逻辑抽象出去
    int minunow=timeNow->tm_min;
    if((minunow-minu>=5&&minu<=minunow)||(minunow+60-minu>=5&&minu>minunow)){
        LOGD("Times accured for all surfaces in past 5 minutes :");
        int i=1;
        for(i=1;i<=cnt;i++){
            LOGD("accured time for surface %lu is %lu",i,times[i]);
            times[i]=0;
        }
        minu=minunow;
    }
    times[id]++;
    if (old_eglSwapBuffers == -1)
        LOGD("error\n");
    //LOGD("New eglSwapBuffer %lu %lu %lu",a,minu,dog);
    LOGD("new_eglSwapBuffers");
    return old_eglSwapBuffers(dpy, surface);
}

void* get_module_base(pid_t pid, const char* module_name)
{
    FILE *fp;
    long addr = 0;
    char *pch;
    char filename[64];
    char line[1024];

    LOGD("%d %s\n",pid,module_name);

    if (pid < 0) {
        /* self process */
        snprintf(filename, sizeof(filename), "/proc/self/maps", pid);
    } else {
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }

    fp = fopen(filename, "r");

    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp)) {
            //LOGD("%s\n",line);
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

//#define LIBSF_PATH  "/system/vendor/lib64/egl/libGLES_mesa.so"
//#define LIBSF_PATH  "/system/lib64/libsurfaceflinger.so"
#define LIBSF_PATH  "/system/lib64/libEGL.so"
int hook_eglSwapBuffers()
{
    old_eglSwapBuffers = eglSwapBuffers;
    LOGD("Orig libGLES = %p\n", old_eglSwapBuffers);
    void * base_addr = get_module_base(getpid(), LIBSF_PATH);
    LOGD("libGLES_mesa.so address = %p\n", base_addr);

    int fd;
    fd = open(LIBSF_PATH, O_RDONLY);
    if (-1 == fd) {
        LOGD("error\n");
        return -1;
    }

    Elf64_Ehdr ehdr;
    read(fd, &ehdr, sizeof(Elf64_Ehdr));

//    void* handle = dlopen("LIBSF_PATH", RTLD_LAZY);
//    void* funcaddr = dlsym(handle, "eglSwapBuffers");
//    LOGD("[+] libGLES_mesa.so eglSwapBuffers = %llx \n",funcaddr);

    unsigned long shdr_addr = ehdr.e_shoff;
    int shnum = ehdr.e_shnum;
    int shent_size = ehdr.e_shentsize;
    unsigned long stridx = ehdr.e_shstrndx;

    Elf64_Shdr shdr;
    lseek(fd, shdr_addr + stridx * shent_size, SEEK_SET);
    read(fd, &shdr, shent_size);

    char * string_table = (char *)malloc(shdr.sh_size);
    lseek(fd, shdr.sh_offset, SEEK_SET);
    read(fd, string_table, shdr.sh_size);
    lseek(fd, shdr_addr, SEEK_SET);

    int i;
    uint64_t out_addr = 0;
    uint64_t out_size = 0;
    uint64_t got_item = 0;
    int64_t got_found = 0;

    for (i = 0; i < shnum; i++) {
        read(fd, &shdr, shent_size);
        if (shdr.sh_type == SHT_PROGBITS) {
            int name_idx = shdr.sh_name;
            if (strcmp(&(string_table[name_idx]), ".got.plt") == 0
                || strcmp(&(string_table[name_idx]), ".got") == 0) {
                out_addr = base_addr + shdr.sh_addr;
                out_size = shdr.sh_size;
                LOGD("name found");

                for (int j = 0; j < out_size; j += 8) {
                    got_item = *(uint64_t *)(out_addr + j);
                    //LOGD("got_item: %llx %llx",got_item,old_eglSwapBuffers);
                    if (got_item  == old_eglSwapBuffers) {
                        LOGD("Found eglSwapBuffers in got\n");
                        got_found = 1;

                        uint64_t page_size = getpagesize();
                        uint64_t entry_page_start = (out_addr + j) & (~(page_size - 1));
                        mprotect((uint64_t *)entry_page_start, page_size, PROT_READ | PROT_WRITE);
                        *(uint64_t *)(out_addr + j) = new_eglSwapBuffers;

                        break;
                    } else if (got_item == new_eglSwapBuffers) {
                        LOGD("Already hooked\n");
                        break;
                    }
                }
                if (got_found)
                    break;
            }
        }
    }

    free(string_table);
    close(fd);
}

int hook_entry(char * a){
    LOGD("Hook success\n");
    LOGD("Start hooking\n");
    hook_eglSwapBuffers();
    return 0;
}
