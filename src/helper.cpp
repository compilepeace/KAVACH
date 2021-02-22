

#include "kavach.h"

#define BLOCK_SIZE 0x200


/* Dumps the process address space to STDERR via /proc/self/maps */
void dump_process_memory () {
    char procmem;
    
    int pfd = open ("/proc/self/maps", O_RDONLY);
    if (pfd == -1) {
        perror ("while opening /proc/self/maps\n");
    }

    while (read (pfd, &procmem, 1) != 0) {
        fprintf (stderr, "%c", procmem);
    }
    fprintf (stderr, "\n");
} 


/* perror() information to debug */
void log (std::string source, std::string func, int line_no, std::string error_string) {
    
    std::string es = BOLDRED "[-] " RESET "(" BOLDBLUE + source + RESET ", " YELLOW 
                     + func +  RESET ", " CYAN  + std::to_string(line_no) 
                     + RESET ") => " + error_string;
                    
    char buffer[es.length() + 1];

    sprintf (buffer, "%s", es.c_str());
    perror (buffer);
}


/* print debug messages to stderr */
void debug_msg (std::string debug_string) {
    
    std::string ds = BOLDGREEN "[+] " MAGENTA + debug_string + RESET"\n";
    
    fprintf (stderr, "%s",ds.c_str());
} 



/* dump a range of memory : [addr, addr + len) */ 
void dump_memory_range (void *addr, size_t len){    
    /* Used for debugging: Prints the hexdump memory mapping of [addr, addr+len] */
    int lcount = 0;
    uint8_t *ptr = (uint8_t *)addr; 
    unsigned int offset = 0;

    fprintf (stderr, "\n-x-x-x-x-x- " RED "Hexdump Rocks" RESET " -x-x-x-x-x-\n");
    fprintf (stderr, BLUE "\n%08x: " RESET, offset);
    
    // print padding
    size_t dspace = 16 - ((len % 16) ? (len % 16): 0);
    size_t sspace = dspace/4;
    size_t padding = (dspace * 2) + sspace;
    for (size_t i = 0; i < len; ++i){
        ++lcount;
        ++offset;

        // print the hex representation of byte pointed to by *ptr
        fprintf (stderr, GREEN "%02x" RESET, (*ptr & 0xff));
        ++ptr;

        if (!(lcount % 4))
            fprintf (stderr, " ");

        if (!(lcount % 16) or (i == len-1)){
            // print padding before printing ASCII repr
            if (i == len-1 and (lcount % 16)){
                while (padding--) 
                    fprintf(stderr, " ");
            }        

            // print the corresponding ASCII representation of byte pointed to by *ptr
            fprintf (stderr, "\t | ");
            for (uint8_t *start = (ptr - 16); start != ptr; ++start){
                if (*start >= 0x21 and *start <= 0x7e){
                    // printable range
                    fprintf (stderr, YELLOW "%c" RESET, *start);
                }
                else{
                    // Non-printable range
                    fprintf (stderr, RED "." RED);
                }
            }
            fprintf (stderr, BLUE "\n%08x: " RESET, offset);
            lcount = 0;
        }
    }
    fprintf (stderr, "\n\n");
}


/* displays [user_string + error_string] for mmap() call to STDERR */ 
void mmap_error (std::string error_string, int &error){
    switch (error)
    {
        case EACCES:
            error_string += "file may not be a regular file (or check open() and mmap() PROT FLAGS)";
            return;
        case EBADF: 
            error_string += "given file descriptor is not valid";
            return;
        case EAGAIN:
            error_string += "file has been locked via a file lock";
            return;
        case EINVAL:
            error_string += "one of more parameters to mmap are invalid";
            return;
        case ENFILE:
            error_string += "system wide limit on open files has been reached";
            return;
        case ENOMEM:
            error_string += "process address space does not have enough memory";
            return;
        case EOVERFLOW:
            error_string += "the size of mapping (addr+len) exceeds the size of process address space";
            return;
        case EPERM:
            error_string += "check file permissions";
            return;
        default:
            error_string += "some least expected errorno value occured";
            return;
    }
    log (__FILE__, __FUNCTION__, __LINE__, error_string);
}


/* displays [user_string + error_string] for sendfile() call to STDERR */
void sendfile_error (std::string error_string, int &error) {
    switch (error)
    {
        case ESPIPE:
            error_string += "offset is not NULL but the input file is not seek(2)-able";
            return;
        case EOVERFLOW:
            error_string += "count is too large, the operation would result in exceeding the maximum size of either the input file or the output file";
            return;
        case ENOMEM:
            error_string += "Insufficient memory to read from in_fd";
            return;
        case EIO:
            error_string += "Unspecified error while reading from in_fd";
            return;
        case EINVAL:
            error_string += "Descriptor is not valid or locked, or an mmap(2)-like operation is not available for in_fd, or count is negative";
            return;
        case EFAULT:
            error_string += "Bad address";
            return;
        case EBADF:
            error_string += "The input file was not opened for reading or the output file was not opened for writing";
            return;
        case EAGAIN:
            error_string += "Nonblocking I/O has been selected using O_NONBLOCK and the write would block";
            return;
        default:
            error_string += "some least expected errorno value occured";
            return;
    }
    log (__FILE__, __FUNCTION__, __LINE__, error_string);
}