#include <unistd.h>
#include <dlfcn.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <execinfo.h>
#include <mach-o/getsect.h>
#include <mach-o/dyld.h>

#define DYLD_INTERPOSE(_replacment,_replacee) \
__attribute__((used)) static struct{ const void* replacment; const void* replacee; } _interpose_##_replacee \
__attribute__ ((section ("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacment, (const void*)(unsigned long)&_replacee };

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

static int      g_initialized = 0;

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

static t_alloc_block *g_alloc_head = NULL;

static void report_leaks()
{
    t_alloc_block *blk;
    char    **strs;
    int i;

    if (!g_alloc_head)
    {
        printf("No leaks !!!\n");
        return ;
    }

    printf("\nReporting leaks :\n\n");
    for (blk = g_alloc_head; blk; blk = blk->next)
    {
        printf(ANSI_CODE_BLINK ANSI_CODE_WHITE ANSI_CODE_UNDERLINE "%zu bytes" ANSI_CODE_RESET " at " ANSI_CODE_BG_BLUE ANSI_CODE_WHITE "%p" ANSI_CODE_RESET "\n", blk->size, blk->base);
        strs = backtrace_symbols(blk->callstack, blk->nframes);
        if (strs)
        {
            for (i = 0; i < blk->nframes; ++i)
            {
                puts(strs[i]);
            }
            printf("\n\n");
            free(strs);
        }
    }
}

__attribute__((constructor))
void leakanalyzer_init()
{
    atexit(report_leaks);

    g_initialized = 1;
}

void    *pMalloc(size_t sz)
{
    t_alloc_block   *blk;
    void            *base;

    base = malloc(sz);
    if (!base)
        return (NULL);
    if (g_initialized)
    {
        blk = malloc(sizeof(*blk));

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
    }
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

void    pFree(void *ptr)
{
    t_alloc_block *blk;
    t_alloc_block *tmp;

    if ((blk = find_block(ptr)) != NULL)
    {
        if (blk->prev)
            blk->prev->next = blk->next;
        if (blk->next)
            blk->next->prev = blk->prev;
        if (blk == g_alloc_head)
            g_alloc_head = blk->next;
        free(blk);
    }
    free(ptr);
}

DYLD_INTERPOSE(pMalloc, malloc);
DYLD_INTERPOSE(pFree, free);
