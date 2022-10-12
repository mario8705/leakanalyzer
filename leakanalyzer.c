#include <unistd.h>
#include <dlfcn.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <execinfo.h>
#include <mach-o/getsect.h>
#include <mach-o/dyld.h>

#  define ANSI_CODE_RESET      "\033[00m"
#  define ANSI_CODE_BOLD       "\033[1m"
#  define ANSI_CODE_DARK       "\033[2m"
#  define ANSI_CODE_UNDERLINE  "\033[4m"
#  define ANSI_CODE_BLINK      "\033[5m"
#  define ANSI_CODE_REVERSE    "\033[7m"
#  define ANSI_CODE_CONCEALED  "\033[8m"
#  define ANSI_CODE_GRAY       "\033[30m"
#  define ANSI_CODE_GREY       "\033[30m"
#  define ANSI_CODE_RED        "\033[31m"
#  define ANSI_CODE_GREEN      "\033[32m"
#  define ANSI_CODE_YELLOW     "\033[33m"
#  define ANSI_CODE_BLUE       "\033[34m"
#  define ANSI_CODE_MAGENTA    "\033[35m"
#  define ANSI_CODE_CYAN       "\033[36m"
#  define ANSI_CODE_WHITE      "\033[37m"
#  define ANSI_CODE_BG_GRAY    "\033[40m"
#  define ANSI_CODE_BG_GREY    "\033[40m"
#  define ANSI_CODE_BG_RED     "\033[41m"
#  define ANSI_CODE_BG_GREEN   "\033[42m"
#  define ANSI_CODE_BG_YELLOW  "\033[43m"
#  define ANSI_CODE_BG_BLUE    "\033[44m"
#  define ANSI_CODE_BG_MAGENTA "\033[45m"
#  define ANSI_CODE_BG_CYAN    "\033[46m"
#  define ANSI_CODE_BG_WHITE   "\033[47m"

extern char **environ;

static int run_process_sync(char *path, char **argv)
{
    pid_t   pid;

    if ((pid = fork()) < 0)
        return (-1);
    if (pid == 0)
    {
        // close(2);

        if (execve(path, argv, environ) < 0)
            perror("execve");

        _exit(1);
    }
    waitpid(pid, NULL, 0);
    return (0);
}

uint64_t StaticBaseAddress(void)
{
    const struct segment_command_64* command = getsegbyname("__TEXT");
    uint64_t addr = command->vmaddr;
    return addr;
}

intptr_t ImageSlide(void)
{
    char path[1024];
    uint32_t size = sizeof(path);
    if (_NSGetExecutablePath(path, &size) != 0) return -1;
    for (uint32_t i = 0; i < _dyld_image_count(); i++)
    {
        if (strcmp(_dyld_get_image_name(i), path) == 0)
            return _dyld_get_image_vmaddr_slide(i);
    }
    return 0;
}

uint64_t DynamicBaseAddress(void)
{
    return StaticBaseAddress() + ImageSlide();
}

static void    *g_libcHandle;

static void log(const char *s)
{
    size_t len;

    len = strlen(s);
    write(2, s, len);
}

typedef void*(*t_malloc_fn)(size_t);
typedef void(*t_free_fn)(void *);

typedef struct s_alloc_block
{
    const char  *file;
    int         line;
    const char  *func;

    void        *base;
    size_t      size;

    void        *callstack[32];
    int         nframes;

    struct s_alloc_block *prev;
    struct s_alloc_block *next;
} t_alloc_block;

static t_malloc_fn g_ref_malloc = NULL;
static t_free_fn g_ref_free = NULL;

static t_alloc_block *g_alloc_head = NULL;

static void report_leaks()
{
    t_alloc_block *blk;
    char    **strs;
    int i;

    printf("\nReporting leaks :\n");
    if (!g_alloc_head)
        printf("No leaks !!!\n");
    for (blk = g_alloc_head; blk; blk = blk->next)
    {
        printf(ANSI_CODE_BLINK ANSI_CODE_WHITE ANSI_CODE_UNDERLINE "%zu bytes" ANSI_CODE_RESET " at " ANSI_CODE_BG_BLUE ANSI_CODE_WHITE "%p" ANSI_CODE_RESET "\n", blk->size, blk->base);
        strs = backtrace_symbols(blk->callstack, blk->nframes);
        if (strs)
        {
            for (i = 1; i < blk->nframes; ++i)
            {
                char *argv[8];

                argv[0] = "atos";
                argv[1] = "-o";
                argv[2] = "minishell";
                argv[3] = "-l";
                asprintf(&argv[4], "%p", DynamicBaseAddress());
                asprintf(&argv[5], "%p", blk->callstack[i]);
                argv[6] = NULL;

                run_process_sync("/usr/bin/atos", argv);

                free(argv[4]);
                free(argv[5]);
            }
            printf("\n\n");
            free(strs);
        }
    }
}

static void handle_siginfo()
{
    exit(1);
}

__attribute__((constructor))
void leakanalyzer_init()
{
    printf("dynamic base address (%0llx) = static base address (%0llx) + image slide (%0lx)\n", DynamicBaseAddress(), StaticBaseAddress(), ImageSlide());

    if (!(g_libcHandle = dlopen("/usr/lib/libSystem.B.dylib", RTLD_LAZY)))
    {
        log("Warning: could not open libc shared library\n");
        return ;
    }

    g_ref_malloc = dlsym(g_libcHandle, "malloc");
    if (!g_ref_malloc)
    {
        log("Warning: Could not find malloc symbol\n");
    }

    g_ref_free = dlsym(g_libcHandle, "free");
    if (!g_ref_free)
    {
        log("Warning: Could not find free symbol\n");
    }

    atexit(report_leaks);
    signal(SIGINFO, handle_siginfo);
}

void    *malloc(size_t sz)
{
    t_alloc_block   *blk;
    void            *base;

    if (!g_ref_malloc)
        return (NULL);
    base = g_ref_malloc(sz);
    if (!base)
        return (NULL);
    blk = g_ref_malloc(sizeof(*blk));

    blk->file = NULL;
    blk->line = -1;
    blk->func = NULL;
    
    blk->base = base;
    blk->size = sz;

    blk->prev = NULL;
    blk->next = g_alloc_head;
    if (g_alloc_head)
        g_alloc_head->prev = blk;
    g_alloc_head = blk;

    blk->nframes = backtrace(blk->callstack, 32);

    return (base);
}

static t_alloc_block *find_block(void *base)
{
    t_alloc_block *blk;

    for (blk = g_alloc_head; blk; blk = blk->next)
    {
        if (blk->base == base)
            return (blk);
    }
    return (NULL);
}

void    free(void *ptr)
{
    t_alloc_block *blk;
    t_alloc_block *tmp;

    if (!g_ref_free || !ptr)
        return ;
    blk = find_block(ptr);
    if (!blk)
    {
        // fprintf(stderr, "Warning: Block not found (double free or dangling pointer)\nPointer: %p\n", ptr);
        return ;
    }

    if (blk->prev)
        blk->prev->next = blk->next;
    if (blk->next)
        blk->next->prev = blk->prev;
    if (blk == g_alloc_head)
        g_alloc_head = blk->next;

    g_ref_free(ptr);
    g_ref_free(blk);
}
