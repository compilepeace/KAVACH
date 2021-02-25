/********************************************************************************
 * Author   : Abhinav Thakur                                                    *
 * Email    : compilepeace@gmail.com                                            *
 * Filename : pack.cpp                                                          *
 *                                                                              *
 * Description: Module responsible for packing target files into                *
 *              <[of_name].kgs> binary.                                         *
 *                                                                              *
 * Code Flow: <main> => <pack>                                                  *
 *                                                                              * 
 ********************************************************************************/


#include "kavach.h"

/* Function Prototypes */
static int      create_copy             (std::string &out_filename, int kfd);
static bool     inject_signature        (int fd, uint64_t signature);
static bool     load_kavach_object      (std::string &target_path, Kavach &ko, std::string &key);
static bool     load_fpn                (std::string &target_path, std::vector<Fhdr> &fht, std::vector<char> &nametab, std::vector<std::vector<uint8_t>> &payload, std::string &key);
static char*    create_string_copy      (std::string &original_string);
static ssize_t  add_to_nametab          (std::string &target_path, std::vector<char> &nametab, bool is_dir);
static uint64_t load_archive_payload    (std::string &target_path, const uint64_t &size, std::vector< std::vector<uint8_t> > &payload, std::string &key, Fhdr::encrypt &etype);
static bool     attach_ko               (int sfxfd, Kavach &ko);
static bool     patch_sfx_metadata      (int sfxfd, uint8_t *map, Kavach &ko);

/* [pack.cpp]: global data */
static uint64_t total_archive_size  = 0;
static uint64_t total_archive_count = 0;
static size_t   cur_payload_offset  = 0;



/* packs files at 'target' location into './<of_name>.FILE_EXTENSION'   *
 * obfuscated using <key>.                                              */
bool pack (int kfd, std::string &target_path, std::string &key, std::string &of_name) {
    
    Kavach      ko;
    uint8_t     *map;
    int         sfxfd;
    struct stat sfxsb;


    /* create a copy of kavach binary named [of_name].FILE_EXTENSION */
    of_name += FILE_EXTENSION;
    sfxfd = create_copy (of_name, kfd);
    if (sfxfd == -1) {
        log ( __FILE__, __FUNCTION__, __LINE__, " while creating kavach copy (SFX)");
        return false;
    }

    if (fstat (sfxfd, &sfxsb) == -1) {
        log (__FILE__, __FUNCTION__, __LINE__, "while fstat'ing SFX");
        return false;
    }

    
    /* injecting SIGNATURE (defined in kavach.h) identifying it as packed binary */
    inject_signature (sfxfd, PACK_SIGNATURE);

    /* load Kavach object */
    if (load_kavach_object (target_path, ko, key) == false) {
        log (__FILE__, __FUNCTION__, __LINE__, "while loading Kavach File Header Table");
        return false;
    }


    /* write Kavach object to End Of Kavach binary (sfxfd). Populate Kavach   *
     * Header too before writing                                            */
    if (attach_ko (sfxfd, ko) == false) {
        log (__FILE__, __FUNCTION__, __LINE__, "while writing kavach object");
        return false;
    }

    /* map SFX binary */
    map = (uint8_t *) mmap (NULL, sfxsb.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, sfxfd, 0);
    if (map == MAP_FAILED) {
        mmap_error ("while mmap'ing SFX", errno);
        return false;
    }

    /********************************************************************
     * Tamper SHT & PHT                                                 *
     * > Patch .kavach shdr entry to account for kbf (kavach binary     *
     *   format). This is done to ensure that programs like `strip`     *
     *   doesn't remove unaccounted archived content.                   *
     ********************************************************************/
    patch_sfx_metadata (sfxfd, map, ko);


    munmap ((void *)map, sfxsb.st_size);
    close (sfxfd);
    return true;
}



/* Patch SFX's SHT entry named .kavach to account for ko.                   *
 * Returns false in case of failure and true for success                    */
static bool patch_sfx_metadata (int sfxfd, uint8_t *map, Kavach &ko) {

    Elf64_Shdr  kshdr;
    // Elf64_Phdr  kphdr;
    Elf64_Ehdr  *ehdr       = (Elf64_Ehdr *) map;
    Elf64_Shdr  *sht        = (Elf64_Shdr *) &map[ehdr->e_shoff];
    // Elf64_Phdr  *pht        = (Elf64_Phdr *) &map[ehdr->e_phoff];
    char        *shstrtab   = (char *) &map[sht[ehdr->e_shstrndx].sh_offset];
    std::string section_name;
    // uint64_t    kvaddr;

/*
    // parse pht: to calculate virtual memory address (p_vaddr)
    for (int i = (ehdr->e_phnum - 1); i >= 0; --i) {

        // we want archive content to be loaded after the last PT_LOAD segment 
        if (pht[i].p_type == PT_LOAD) {

            kvaddr  = pht[i].p_vaddr + pht[i].p_memsz;          // kvaddr will be placed in next segment 
            kvaddr += (PAGE_SIZE - (kvaddr % PAGE_SIZE));       // since all segments are PAGE_SIZE aligned,
                                                                // this makes kvaddr PAGE_SIZE aligned 

            // ********************************************************************
            //  * Lets make kvaddr congurent to (kshdr.p_offset % p_align). Now,   *
            //  * p_offset will be same as kshdr.sh_offset == KAVACH_BINARY_SIZE & *
            //  * p_align  i.e. PAGE_SIZE (usually 0x1000).                        *
            //  *                                                                  *
            //  * Congruency constraint is mentioned in ELF specification v1.2.    *
            //  * p_vaddr += (p_offset % p_align) - (p_vaddr % p_align)            *
            //  ********************************************************************
            int n   = (KAVACH_BINARY_SIZE % PAGE_SIZE) - (kvaddr % PAGE_SIZE);
            kvaddr += n; 

            break;
        }
    }

    kphdr.p_type        = PT_LOAD;
    kphdr.p_offset      = KAVACH_BINARY_SIZE;
    kphdr.p_vaddr       = kvaddr;
    kphdr.p_paddr       = kvaddr;
    kphdr.p_filesz      = ARCHIVE_SIZE;
    kphdr.p_memsz       = ARCHIVE_SIZE;
    kphdr.p_flags       = PF_R;
    kphdr.p_align       = PAGE_SIZE;

    //  * parse pht: convert first PT_NOTE segment encountered to PT_LOAD  *
    //  * and replace it by kavach phdr                                    *
    for (int i = 0; i < (ehdr->e_phnum); ++i) {
        if (pht[i].p_type == PT_NOTE) {
            memmove (&pht[i], &kphdr, sizeof (Elf64_Phdr));
            break;
        }
    }
*/
 
    kshdr.sh_type       = SHT_PROGBITS;
    kshdr.sh_flags      = SHF_ALLOC;
    //kshdr.sh_addr       = kvaddr;               /* calculated via last PT_LOAD attributes */
    kshdr.sh_addr       = KAVACH_BINARY_SIZE;
    kshdr.sh_offset     = KAVACH_BINARY_SIZE;
    kshdr.sh_size       = ARCHIVE_SIZE;
    kshdr.sh_link       = 0;
    kshdr.sh_info       = 0;
    kshdr.sh_addralign  = 1;                    /* kept 2^0 for simplicity */
    kshdr.sh_entsize    = 1;                    /* since this contains binary data */


    /* parse sht to find .kavach shdr */
    for (int i = 0; i < (ehdr->e_shnum); ++i) {
        section_name = &shstrtab[sht[i].sh_name];
        if ( section_name == SHDR_NAME) {
            kshdr.sh_name = sht[i].sh_name;                 /* already set by compiler  ^_^ */
            memmove (&sht[i], &kshdr, sizeof(Elf64_Shdr));
            break;
        }
    }

    return true;
}



/* load Kavach object with the content of target (file/directory).  */
static bool load_kavach_object (std::string &target_path, Kavach &ko, std::string &key) {

    /* load FHT, archive payload & nametab */
    if (load_fpn (target_path, ko.fht, ko.nametab, ko.payload, key) == false) {
        log (__FILE__, __FUNCTION__, __LINE__, "while loading kavach FHT");
        return false;
    }

    /* load kavach binary header (kbhdr) -  performed at the time of writing all    *
     * components of Kavach object to SFX binary.                                   */

    return true;
}



/* Loads FHT, archive payload (i.e. a vector of strings) and nametab. Depth first recursive parsing is used to create FHT */
static bool load_fpn (std::string &target_path, std::vector<Fhdr> &fht, std::vector<char> &nametab,
                      std::vector<std::vector<uint8_t>> &payload, std::string &key) {

    struct stat tsb;        /* target stat buffer */
    Fhdr cur_fhdr;          /* current file header */


        /* get target file attributes and load it into cur_fhdr */
        if (stat (target_path.c_str(), &tsb) == -1) {
            log (__FILE__, __FUNCTION__, __LINE__, "while fstat'ing <target>");
            return false;
        }
        
            /* Loading file attributes into Fhdr */ 
            cur_fhdr.fh_offset  = 0;                     // set for S_ISDIR(). for S_ISREG(), it is set to cur_payload_offset 
            cur_fhdr.fh_etype   = ENCRYPTION_TYPE;
            cur_fhdr.fh_mode    = tsb.st_mode;
            cur_fhdr.fh_size    = tsb.st_size;
            // while unpacking, we use futimens() that will use this fhdr's timestamp /
            memmove ( &cur_fhdr.fh_time[0], &tsb.st_atim, sizeof (struct timespec) );   // preserving access time 
            memmove ( &cur_fhdr.fh_time[1], &tsb.st_mtim, sizeof (struct timespec) );   // preserving modification time 


        /* file encountered */
        if  ( S_ISREG (tsb.st_mode) ) {
            
            ds = "\tpacking: " + target_path;
            debug_msg (ds);

            /* Load filetype and nametable index attribute of cur_fhdr (implicitly adding filename into nametab vector) */            
            cur_fhdr.fh_ftype   = Fhdr::FT_FILE;
            cur_fhdr.fh_offset  = cur_payload_offset;
            cur_fhdr.fh_namendx = add_to_nametab (target_path, nametab, false);

            /* append current file header (cur_fhdr) into FHT if add_to_nametab() didn't return -1 */ 
            if (cur_fhdr.fh_namendx != (uint64_t ) -1) {
                fht.push_back (cur_fhdr);
            }

            /* Load archive payload */
            uint64_t payload_size = load_archive_payload (target_path, tsb.st_size, payload, key, cur_fhdr.fh_etype);
            if ( payload_size == -1) {
                log (__FILE__, __FUNCTION__, __LINE__, "while loading archive payload");
                return false;
            }

            /* Load fh_offset (i.e. offset to file bodies/payloads) */
            cur_payload_offset += payload_size;
        }


        /* directory encountered */
        else if ( S_ISDIR (tsb.st_mode) ) {
            DIR *dptr;
            struct dirent *dent;
            std::string current_dir = ".";
            std::string parent_dir  = "..";

            ds = "\tpacking: " + target_path;
            debug_msg (ds);

            /* Load filetype attribute, add filename into nametab vector and append cur_fhdr to FHT */
            cur_fhdr.fh_ftype   = Fhdr::FT_DIR;
            cur_fhdr.fh_namendx = add_to_nametab (target_path, nametab, true);
            if (cur_fhdr.fh_namendx != (uint64_t ) -1) {
                fht.push_back (cur_fhdr);
            }
               

                /* open up the directory and recurively load the entries filling up FHT and nametab */
                dptr = opendir (target_path.c_str());
                if (dptr == NULL) {
                    log ( __FILE__, __FUNCTION__, __LINE__, "while open'ing directory ptr" );
                    return false;
                }

                    /* parse directory entries and set errno = 0 to distinguish between an error    *
                     * and end of directory entry stream                                            */
                    errno = 0;   
                    while ( (dent = readdir (dptr)) != NULL ) {
                        if ( (dent->d_type == DT_DIR || dent->d_type == DT_REG) &&
                             (dent->d_name != current_dir && dent->d_name != parent_dir) ) {
                            std::string new_target_path = target_path + "/" + dent->d_name;
                            load_fpn (new_target_path, fht, nametab, payload, key);
                        }
                    }

                if (errno != 0) {
                    es = "while reading directory entries from " + target_path;
                    log (__FILE__, __FUNCTION__, __LINE__, es);
                    return false;
                }

                /* A sentinel value marking as the end of directory contents */
                Fhdr empty_fhdr;
                fht.push_back(empty_fhdr);

                closedir (dptr);
        }

    return true;
}



/* Adds file/directory name to nametab vector . Returns an offset into the nametab or -1 on failure */
static ssize_t add_to_nametab (std::string &target_path, std::vector<char> &nametab, bool is_dir) {
    
    /* add dirname to nametab and get 'cur_fhdr.fh_namendx' */
    uint64_t offset = nametab.size(); 
    char *path_copy;
    std::string name;

    /* create a copy of target_path to pass it to basename () which may modify the passed copy */
    path_copy = create_string_copy (target_path);
    if (path_copy == NULL) {
        log (__FILE__, __FUNCTION__, __LINE__, "while creating path copy");
        return false;
    }

    name = basename (path_copy);
    if ( is_dir && (name == "." || name == "..") ) {
        /* skip directories named '.' and '..' */
        return -1;                                  
    }

    /* add name (of file or directory) to nametab */
    for (char c: name) {
        nametab.push_back (c);
    }
    nametab.push_back ('\x00');


    free (path_copy);
    return offset;
}



/* create a copy from <kfd> and name it <out_filename>.             *
 * Return the freshly newly created file's descriptor               */
static int create_copy (std::string &out_filename, int kfd) {

    struct stat kb_sb;      /* input file stat buffer */
    int ofd;                /* input and output file descriptors */


    if (fstat (kfd, &kb_sb) == -1) {
        log ( __FILE__, __FUNCTION__, __LINE__, " while fstat'ing kavach binary" );
        return -1;
    }

    /* create [out_filename] with mode_t same as [kavach binary] */
    ofd = open (out_filename.c_str(), O_RDWR|O_CREAT|O_EXCL, kb_sb.st_mode);
    if (ofd == -1) {
        log ( __FILE__, __FUNCTION__, __LINE__, " while creating SFX binary" );
        return -1;
    }

    /* copy [kfd] to [out_filename] using sendfile () */
    uint64_t bytes_copied = 0;
    uint64_t total_bytes_copied = 0;
    while ( bytes_copied = sendfile (ofd, kfd, NULL, KAVACH_BINARY_SIZE - total_bytes_copied) ) { 
        
        if (bytes_copied == -1) {   /* error occured */
            sendfile_error ("while copying [kavach binary] -> [out_filename]", errno);
            return -1;
        }

        total_bytes_copied += bytes_copied;
        if (total_bytes_copied == KAVACH_BINARY_SIZE) {
            /* copy complete */
            break;
        }
    }

    return ofd;
}



/* injects signature inside inside ELF header: e_ident[EI_NIDENT]   *
 * i.e. @ offset 0x8 from the beginning                             */
static bool inject_signature (int fd, uint64_t signature) {
    
    if (pwrite (fd, &signature, 0x8, 0x8) != 0x8 ) {
        log ( __FILE__, __FUNCTION__, __LINE__, " while injecting signature" );
        return false;
    }

    return true;
}



/* returns a pointer to copy of os (original string) allocated on heap segment */
static char *create_string_copy (std::string &os) {
    
    size_t os_size = os.length();
    char *copy = (char *) malloc (os_size + 1);
    if (copy == NULL) {
        es = "while malloc'ing " + std::to_string(os_size + 1) + "bytes";
        log (__FILE__, __FUNCTION__, __LINE__, es);
    }

    memmove (copy, os.c_str(), os_size);
    copy[os_size] = '\x00';

    return copy;
}



/* loads the content of <target_path> filename to payload vector. Returns 'payload size' or -1 on failure */
static uint64_t load_archive_payload ( std::string &path, const uint64_t &size, std::vector<std::vector<uint8_t>> &payload,
                                       std::string &key, Fhdr::encrypt &etype) {
    
    int afd;
    std::vector<uint8_t> archive_content;
    archive_content.resize(size);
    

    /* archive file descriptor */
    afd = open (path.c_str(), O_RDONLY);
    if (afd == -1) {
        es = "while open'ing " + path;
        log (__FILE__, __FUNCTION__, __LINE__, es);
        return -1;
    }

    if (read (afd, &archive_content[0], size) != size) {
        es = "while reading from " + path;
        log (__FILE__, __FUNCTION__, __LINE__, es);
        return -1;
    }

    /*  If user supplied --encrypt and --key flags,         * 
     *  scramble <archive_content> with user-supplied <key> */
    if (etype != Fhdr::encrypt::FET_UND) {
        SCRAMBLE::encrypt (archive_content, key, etype);
    }
        
    payload.push_back (archive_content);
    
    
    // fprintf (stderr, "target: %s\n\tsize: %ld\n\tfile content: ", path.c_str(), size);
    // dump_memory_range (&archive_content[0], size);
    
    close (afd);
    return archive_content.size();
}



/***********************************************************************************************
 * writes kavach object to SFX binary represented by <sfxfd> in addition to loading ko.header. *
 * Returns false on failure.                                                                   *
 * NOTE: All offsets being written to kavach binary header are relative offsets (to the start  *
 *       of Kbhdr (unpack it accordingly).                                                     *
 ***********************************************************************************************/
static bool attach_ko (int sfxfd, Kavach &ko) {
    
    uint64_t bytes_written;
    uint64_t write_size;
    uint64_t offset;


    /* seek to the end of file + sizeof(Kbhdr) */
    offset = lseek (sfxfd, sizeof(Kbhdr), SEEK_END);
    if ( offset == -1 ) {
        log (__FILE__, __FUNCTION__, __LINE__, "while lseek'ing to the end of SFX + sizeof(Kbhdr)");
        return false;
    }
    ko.header.k_fhtoff = offset - KAVACH_BINARY_SIZE;   

    /* write FHT */
    ko.header.k_fhentsize   = sizeof (Fhdr);
    ko.header.k_fhnum       = ko.fht.size();
    write_size = sizeof(Fhdr);
    for (auto fhdr: ko.fht) {
        if (write (sfxfd, &fhdr, write_size) != write_size) {
            es  = "while writing file header of: ";
            es += &ko.nametab[fhdr.fh_namendx];
            es += "to SFX binary";
            log (__FILE__, __FUNCTION__, __LINE__, es);
            return false;
        }
    }

    /* write archive payload */
    offset = lseek (sfxfd, 0, SEEK_CUR);
    if (offset == -1) {
        log (__FILE__, __FUNCTION__, __LINE__, "while loading ko.header.k_payloadoff (lseek failed)");
        return false;
    }
    ko.header.k_payloadoff = offset - KAVACH_BINARY_SIZE;

    uint64_t current_offset = 0;
    for (auto file: ko.payload) {

        write_size = file.size();
        if (write (sfxfd, &file[0], write_size) != write_size) {
            es = "while writing payload offset: " + std::to_string (current_offset);
            log (__FILE__, __FUNCTION__, __LINE__, es);
            return false;
        }
        current_offset += write_size;
    }

    ko.header.k_payloadsz = current_offset;
    if (current_offset != cur_payload_offset) {
        log (__FILE__, __FUNCTION__, __LINE__, "Payload not completely written to SFX binary");
        return false;
    }


    /* write names table to file */
    offset = lseek (sfxfd, 0, SEEK_CUR);
    if (offset == -1) {
        log (__FILE__, __FUNCTION__, __LINE__, "while loading ko.header.nametaboff (lseek failed)");
        return false;
    }
    ko.header.k_nametaboff = offset - KAVACH_BINARY_SIZE;

    write_size = ko.nametab.size();
    if (write (sfxfd, &ko.nametab[0], write_size) != write_size) {
        log (__FILE__, __FUNCTION__, __LINE__, "while writing ko.nametab to SFX binary");
        return false;
    }

    /* getting size of archive (excluding size of SFX) */
    offset = lseek (sfxfd, 0, SEEK_CUR);
    if (offset == -1) {
        log (__FILE__, __FUNCTION__, __LINE__, "while leek'ing to KBF end (getting ARCHIVE_SIZE)");
        return false;
    }
    else {
        ARCHIVE_SIZE = offset - KAVACH_BINARY_SIZE;
    }

    /* pwrite kavach binary header @ end of SFX's SHT == kavach_start */
    write_size = sizeof(Kbhdr);
    if (pwrite (sfxfd, &ko.header, write_size, KAVACH_BINARY_SIZE) != write_size) {
         log (__FILE__, __FUNCTION__, __LINE__, "while writing kavach header to SFX binary");
         return false;
    }

    return true;
}