/********************************************************************************
 * Author   : Abhinav Thakur                                                    *
 * Email    : compilepeace@gmail.com                                            *
 * Filename : kavach.h                                                          *
 *                                                                              *
 * Description: This module provides an API to other object code binaries along *
 *              with defining kavach binary format (kbf).                       *
 *                                                                              * 
 ********************************************************************************/


#ifndef _KAVACH_H
#define _KAVACH_H


#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <elf.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <libgen.h>

#include <iostream>
#include <string>
#include <vector>
#include <stack>


/* -x--x-x-x-x-x-x-x-x-x-x-x- Blueprints -x-x-x-x--x-x-x-x-x-x-x-x- */

/************************************************************************
 * File Header Structure:                                               *
 *      This structure acts as an entry of the File Header Table.       *
 *      Each entry in FHT stores the below mentioned metadata           *
 *      pertaining to a single file/directory.                          *
 *                                                                      *
 * NOTE: Encryption type is FT_UND (undefined) for FT_DIR (directory).  *
 *       A NULL FHT entry represents the end of current directory       *
 *       contents/entries.                                              *
 *                                                                      *
 ************************************************************************/
class Fhdr {
public:

    enum ftype {
        FT_UND  = 0,        /* undefined: represents a NULL Fhdr entry */
        FT_FILE = 1,        /* a file */
        FT_DIR  = 2         /* a directory */
    };

    enum encrypt {
        FET_UND = 0,        /* NO encryption - archive only */
        FET_XOR = 1         /* XOR encryption */
    };

    /* constructor */
    Fhdr (): fh_namendx(0), fh_offset(0), fh_ftype(FT_UND), 
             fh_etype(FET_UND), fh_mode(0), fh_size(0) { }

    uint64_t            fh_namendx;     /* index into .kavachstrtab */
    uint64_t            fh_offset;      /* offset into the archived payload (i.e. kavach::payload) */
    ftype               fh_ftype;       /* file type */
    encrypt             fh_etype;       /* encryption type applied to data (described by this file header) */
    mode_t              fh_mode;        /* attribute: creation file mode */
    uint64_t            fh_size;        /* attribute: size of data file */
    struct timespec     fh_time[2];     /*  for futimens () syscall 
                                            fh_times[0] -> last access time         : atime (st_atim)
                                            fh_times[1] -> last modification time   : mtime (st_mtim) s*/

    /* Useful methods */
    bool is_dir_end () {
        return (this->fh_ftype == FT_UND) ? true: false;
    }

    void dump(){
		fprintf(stderr, "\n\t^^^^^^^^ File Header ^^^^^^^\n");
		fprintf(stderr, "\tfh_namendx   : 0x%lx \n"
                        "\tfh_offset    : 0x%lx \n"
                        "\tfh_ftype     : 0x%x \n"
                        "\tfh_etype     : 0x%x \n"
                        "\tfh_mode      : 0x%x \n"
                        "\tfh_size      : 0x%lx \n"
                        "\tfh_time[0].s : 0x%lx \n"
                        "\tfh_time[0].ns: 0x%lx \n"
                        "\tfh_time[1].s : 0x%lx \n"
                        "\tfh_time[1].ns: 0x%lx \n",
						fh_namendx, fh_offset, fh_ftype,
                        fh_etype, fh_mode, fh_size,
                        fh_time[0].tv_sec, fh_time[0].tv_nsec,
                        fh_time[1].tv_sec, fh_time[1].tv_nsec);
		fprintf(stderr, "\t^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
	}
};


/************************************************************************
 * Kavach Binary Header:                                                *
 *      Acts as a roadmap to parse the FHT. Stores file offset (i.e.    *
 *      offset from the beginning of binary file) unlike other parts    *
 *      like FHT, payload and nametab which which stores section        *
 *      offsets (i.e. offsets from beginning of some particular         *
 *      section).                                                       *
 *                                                                      *
 * NOTE: Offset to FHT and the number of entries inside FHT are         *
 *       sufficient to parse the entire archived data.                  *
 *                                                                      *
 ************************************************************************/
class Kbhdr {
public:

    /* constructor */
    Kbhdr (): k_fhtoff(0), k_fhnum(0) { }

    /* attributes of binary data */
    uint64_t            k_fhtoff;       /* File Header Table (FHT) offset */
    uint64_t            k_fhnum;        /* number of entries in FHT */
    uint64_t            k_fhentsize;    /* size of each entry in FHT, i.e. sizeof (Fhdr) */
    uint64_t            k_nametaboff;   /* offset to .nametab where all file names are stored */
    uint64_t            k_payloadoff;   /* offset to start of 'archived payload' */
    uint64_t            k_payloadsz;    /* total size of all files included in archived payload */

    /* Useful methods */	
	void dump(){
		fprintf(stderr, "\n\t^^^^^^^^ Kavach Binary Header ^^^^^^^\n");
		fprintf(stderr,	"\tk_fhtoff     : 0x%lx \n"
						"\tk_fhnum      : 0x%lx \n"
                        "\tk_fhentsize  : 0x%lx \n"
                        "\tk_nametaboff : 0x%lx \n"
                        "\tk_payloadoff : 0x%lx \n"
                        "\tk_payloadsz  : 0x%lx \n"
                        ,
						k_fhtoff, k_fhnum, k_fhentsize,
                        k_nametaboff, k_payloadoff, k_payloadsz);
		fprintf(stderr, "\t^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
	}
};


/************************************************************************
 * Kavach Binary Format:                                                *
 *      Describes the layout of Kavach binary format.                   *
 *                                                                      *
 * NOTE: It simply starts with a header (roadmap to FHT) followed by    * 
 *       the FHT, payload and nametab.                                  *
 *                                                                      *
 *                       ___________________   _                        *
 *                      |                   |   \ --->    KUNDAL        *
 *                      |   [ ELF Header ]  |   |      [ packed SFX ]   *
 *                      |___________________|   |                       *
 *                      |                   |   |                       * 
 *                      |      [ PHT ]      |   |                       * 
 *                      |___________________|   | ===> ELF Binary       *
 *                      |                   |   |                       *
 *                      |   [ Sections ]    |   |                       *
 *                      |___________________|   |                       *
 *                      |                   |   |                       *
 *                      |      [ SHT ]      |   |                       *
 *                      |                   |  _/                       *
 *                      ^^^^^^^^^^^^^^^^^^^^^                           *
 *                               ||                                     *
 *                               ||                                     *
 *                            Attached                                  *
 *                               ||                                     *
 *                               ||                                     *
 *                                                                      *
 *                      |^^^^^^^^^^^^^^^^^^^|  _                        *
 *                      |     [ Header ]    |   \                       *
 *                      |      (Kbhdr)      |   |                       *
 *                      |___________________|   |                       *
 *                      |                   |   |                       *
 *                      |      [ FHT ]      |   |                       *
 *                      |                   |   |                       *
 *                      |      -- Fhdr1     |   |                       *
 *                      |      -- Fhdr2     |   |                       *
 *                      |      -- Fhdr3     |   |                       *
 *                      |         ...       |   |                       *
 *                      |         ...       |   |                       *
 *                      |      -- FhdrN     |   | ===> Kavach body      *
 *                      |___________________|   |                       *
 *                      |                   |   |                       *
 *                      |    [ Payload ]    |   |                       *
 *                      |                   |   |                       *
 *                      |      -- File1     |   |                       *
 *                      |      -- File2     |   |                       *
 *                      |      -- File3     |   |                       *
 *                      |          ...      |   |                       *
 *                      |          ...      |   |                       *
 *                      |      -- FileN     |   |                       *
 *                      |___________________|   |                       *
 *                      |                   |   |                       *
 *                      |    [ nametab ]    |   |                       *
 *                      |___________________|  _/                       *
 *                                                                      *
 ************************************************************************/
class Kavach {
public:

    /* constructor */
    Kavach () { }

    /* kavach structure */
    Kbhdr                               header;     /* head */
    std::vector<Fhdr>                   fht;        /* File Header Table */
    std::vector<std::vector<uint8_t>>   payload;    /* actual archive payload (file bodies) */
    std::vector<char>                   nametab;    /* names table to store all file/dir names */
};



/* -x--x-x-x-x-x-x-x-x-x-x-x- MACROS -x--x-x-x-x-x-x-x-x-x-x-x- */
#define RESET   "\033[0m"
#define BLACK   "\033[30m"      /* Black */
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */
#define YELLOW  "\033[33m"      /* Yellow */
#define BLUE    "\033[34m"      /* Blue */
#define MAGENTA "\033[35m"      /* Magenta */
#define CYAN    "\033[36m"      /* Cyan */
#define GREY    "\e[37m"        /* Grey */
#define WHITE   "\033[37m"      /* White */
#define BOLDBLACK   "\033[1m\033[30m"      /* Bold Black */
#define BOLDRED     "\033[1m\033[31m"      /* Bold Red */
#define BOLDGREEN   "\033[1m\033[32m"      /* Bold Green */
#define BOLDYELLOW  "\033[1m\033[33m"      /* Bold Yellow */
#define BOLDBLUE    "\033[1m\033[34m"      /* Bold Blue */
#define BOLDMAGENTA "\033[1m\033[35m"      /* Bold Magenta */
#define BOLDCYAN    "\033[1m\033[36m"      /* Bold Cyan */
#define BOLDWHITE   "\033[1m\033[37m"      /* Bold White */
#define BOLDGREY    "\e[90m"               /* Bold Grey */

#define BRIGHT      "\e[1m"
#define DIM         "\e[2m"
#define UNDERLINE   "\e[4m"
#define BLINK       "\e[5m"
#define INVERT      "\e[7m"
#define HIDDEN      "\e[8m"     /* useful for passwords */
//#define ORANGE      “\e[38;5;202m” 



#define SHDR_NAME       ".kavach"               /* Kavach shdr name                     */
#define FILE_EXTENSION  ".kgs"                  /* (k)avach (g)enerated (s)fx           */
#define PACK_SIGNATURE  0x4c41444e554b0000      /* Karn's KUNDAL (a pair of earrings)   */


/* shared data */
extern int              DESTROY_RELICS;         /* flag set by --destroy-relics         */
extern int              UNPACK_FLAG;
extern int              PACK_FLAG;
extern int              KEY_FLAG;
extern int              OFNAME_FLAG;            /* output filename                      */
extern Fhdr::encrypt    ENCRYPTION_TYPE;
extern uint64_t         KAVACH_BINARY_SIZE;     /* size from offset 0 -> SHT end        */
extern uint64_t         ARCHIVE_SIZE;           /* size from SHT end  -> KBF end        */
extern uint64_t         PAGE_SIZE;              /* sysconf (_SC_PAGESIZE);              */
extern std::string      es, ds;                 /* error|debug strings                  */




/* -x--x-x-x-x-x-x-x-x-x-x-x- Exported API -x--x-x-x-x-x-x-x-x-x-x-x- */

/********************************************************************
 *                                                                  * 
 * NOTE: Below are the functions exported by respective object      *
 *       files. Functions internal to these object files are        *
 *       declared inside the respective source files.               * 
 *                                                                  *
 ********************************************************************/

/* pack.o */
bool pack                   (int kfd, std::string &pack_target, std::string &password_key, std::string &out_filename);

/* unpack.o */
bool unpack                 (int kfd, std::string &target_location, std::string &password_key);

/* parse_cmdline_args.o */
void parse_cmdline_args     (int argc, char **argv, std::string &password_key, std::string &pack_target, std::string &destination_dir, std::string &out_filename);
void print_usage            ();

/* encrypt.o */
namespace SCRAMBLE {
    bool encrypt            (std::vector<uint8_t> &payload, std::string &key, Fhdr::encrypt &etype);
}
void pxor                   (std::vector<uint8_t> &payload, std::string &key);

/* decrypt.o */
namespace DESCRAMBLE {
    bool decrypt            (std::vector<uint8_t> &payload, std::string &key, Fhdr::encrypt &etype);
}


/* helper.o */
void dump_process_memory    ();                                         /* read /proc/self/maps */
void dump_memory_range      (void *addr, size_t len);                   /* dump a region of memory */
void log                    (std::string source, std::string function, int line_no, std::string error_string);
void debug_msg              (std::string debug_msg);
void mmap_error             (std::string error_string, int &error);    
void sendfile_error         (std::string error_string, int &error);


#endif      /* _KAVACH_H */