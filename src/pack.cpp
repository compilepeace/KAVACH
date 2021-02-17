/*
 * Author   : Abhinav Thakur
 * Email    : compilepeace@gmail.com
 * Filename : pack.cpp
 *
 * Description: Module responsible for packing target files into <[of_name].kgs> binary.
 * 
 * Code Flow: <main> => <pack>   
 *
*/

#include "kavach.h"

/* Function Prototypes */
static int      create_copy             (std::string &out_filename, int kfd);
static bool     inject_signature        (int fd, uint64_t signature);
static bool     load_kavach_object      (std::string &target_path, Kavach &ko);
static bool     load_fpn                (std::string &target_path, std::vector<Fhdr> &fht, std::vector<char> &nametab, std::vector<std::vector<uint8_t>> &payload);
static char*    create_string_copy      (std::string &original_string);
static ssize_t  add_to_nametab          (std::string &target_path, std::vector<char> &nametab, bool is_dir);
static uint64_t load_archive_payload    (std::string &target_path, const uint64_t &size, std::vector< std::vector<uint8_t> > &payload);
static bool     attach_ko               (int ofd, Kavach &ko);

/* global data */
static uint64_t total_archive_size  = 0;
static uint64_t total_archive_count = 0;
static size_t   cur_payload_offset  = 0;


/* packs files at 'target' location into './<of_name>.FILE_EXTENSION'   *
 * obfuscated using <key>.                                              */
bool pack (int kfd, std::string &target_path, std::string &key, std::string &of_name) {
    
    Kavach ko;
    int ofd = 0;


    /* create a copy of kavach binary named [of_name].FILE_EXTENSION */
    of_name += FILE_EXTENSION;
    ofd = create_copy (of_name, kfd);
    if (ofd == -1) {
        log ( __FILE__, __FUNCTION__, __LINE__, " while creating kavach copy");
        return false;
    }
    
    /* injecting SIGNATURE (defined in kavach.h) identifying it as packed binary */
    inject_signature (ofd, PACK_SIGNATURE);

    /* load Kavach object */
    if (load_kavach_object (target_path, ko) == false) {
        log (__FILE__, __FUNCTION__, __LINE__, "while loading Kavach File Header Table");
        return false;
    }

    /* print nametab */
    // for (auto hdr: ko.fht) {
    //     hdr.dump();
    //     fprintf (stderr, "index: %ld: str: %s\n", hdr.fh_namendx, &ko.nametab[hdr.fh_namendx]);
    // }

    /* write Kavach object to End Of Kavach binary (odf). Populate Kavach Header too.  */
    if (attach_ko (ofd, ko) == false) {
        log (__FILE__, __FUNCTION__, __LINE__, "while writing kavach object");
        return false;
    }

    /* tamper SHT - add .kavach & .nametab section to accomodate kbf        *
     * (kavach binary format) so that programs like `strip` doesn't remove  *
     * archived content.                                                    */


    


    /* write file content to archive into kavach                            */


    /* fixup the remaining ko.header entries */


    /* tamper PHT - convert PT_NOTE to PT_LOAD section to accomodate kbf    *
     * (kavach binary format)                                               */


    close (ofd);
    return true;
}



/* load Kavach object with the content of target (file/directory).  */
static bool load_kavach_object (std::string &target_path, Kavach &ko) {

    /* load FHT, archive payload & nametab */
    if (load_fpn (target_path, ko.fht, ko.nametab, ko.payload) == false) {
        log (__FILE__, __FUNCTION__, __LINE__, "while loading kavach FHT");
        return false;
    }

    /* load kavach binary header (kbhdr) -                                      *    
     * performed after writing all components of Kavach object to kavach binary */

    return true;
}



/* Loads FHT, archive payload (i.e. a vector of strings) and nametab. Depth first recursive parsing is used to create FHT */
static bool load_fpn (std::string &target_path, std::vector<Fhdr> &fht, std::vector<char> &nametab, std::vector<std::vector<uint8_t>> &payload) {

    struct stat tsb;        /* target stat buffer */
    Fhdr cur_fhdr;          /* current file header */


        /* get target file attributes and load it into cur_fhdr */
        if (stat (target_path.c_str(), &tsb) == -1) {
            log (__FILE__, __FUNCTION__, __LINE__, "while fstat'ing <target>");
            return false;
        }
        
            /* Loading file attributes into Fhdr */ 
            cur_fhdr.fh_offset = 0;                     // set for S_ISDIR(). for S_ISREG(), it is set to cur_payload_offset 
            if (ENCRYPTION_TYPE == E_TYPE_NONE) {
                cur_fhdr.fh_etype = Fhdr::FET_UND;
            }
            else if (ENCRYPTION_TYPE == E_TYPE_XOR) {
                cur_fhdr.fh_etype = Fhdr::FET_XOR;
            }
            cur_fhdr.fh_mode    = tsb.st_mode;
            cur_fhdr.fh_size    = tsb.st_size;
            // while unpacking, we use futimens() that will use this fhdr's timestamp /
            memmove ( &cur_fhdr.fh_time[0], &tsb.st_atim, sizeof (struct timespec) );   // preserving access time 
            memmove ( &cur_fhdr.fh_time[1], &tsb.st_mtim, sizeof (struct timespec) );   // preserving modification time 


        /* file encountered */
        if  ( S_ISREG (tsb.st_mode) ) {
            
            /* Load filetype and nametable index attribute of cur_fhdr (implicitly adding filename into nametab vector) */            
            cur_fhdr.fh_ftype   = Fhdr::FT_FILE;
            cur_fhdr.fh_offset  = cur_payload_offset;
            cur_fhdr.fh_namendx = add_to_nametab (target_path, nametab, false);

            /* append current file header (cur_fhdr) into FHT if add_to_nametab() didn't return -1 */ 
            if (cur_fhdr.fh_namendx != (uint64_t ) -1) {
                fht.push_back (cur_fhdr);
            }

            /* Load archive payload */
            uint64_t payload_size = load_archive_payload (target_path, tsb.st_size, payload);
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

            /* Load filetype attribute, add filename into nametab vector and append cur_fhdr to FHT */
            cur_fhdr.fh_ftype = Fhdr::FT_DIR;
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

                    errno = 0;          /* to distinguish between an error and end of directory entry stream */
                    while ( (dent = readdir (dptr)) != NULL ) {
                        if ( (dent->d_type == DT_DIR || dent->d_type == DT_REG) &&
                             (dent->d_name != current_dir && dent->d_name != parent_dir) ){
                            std::string new_target_path = target_path + "/" + dent->d_name;
                            load_fpn (new_target_path, fht, nametab, payload);
                        }
                    }

                if (errno != 0) {
                    es = "while reading directory entries from " + target_path;
                    log (__FILE__, __FUNCTION__, __LINE__, es);
                    return false;
                }

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
static uint64_t load_archive_payload (std::string &path, const uint64_t &size, std::vector<std::vector<uint8_t>> &payload) {
    
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

    payload.push_back (archive_content);
    
    
    // fprintf (stderr, "target: %s\n\tsize: %ld\n\tfile content: ", path.c_str(), size);
    // dump_memory_range (&archive_content[0], size);
    
    close (afd);
    return archive_content.size();
}



/* writes kavach object to SFX binary represented by <ofd> in addition to loading ko.header. *
 * Returns false on failure */
static bool attach_ko (int ofd, Kavach &ko) {
    
    uint64_t kavach_start;
    uint64_t bytes_written;
    uint64_t write_size;


    /* get offset of to start of kavach binary format (Kbhdr) */
    kavach_start =  lseek (ofd, 0, SEEK_END);
    if (kavach_start == -1) {
        log (__FILE__, __FUNCTION__, __LINE__, "while lseek'ing to the end of SFX binary");
        return false;
    }

    /* seek to the end of file + sizeof(Kbhdr) */
    ko.header.k_fhtoff = lseek (ofd, sizeof(Kbhdr), SEEK_END);
    if ( ko.header.k_fhtoff == -1 ) {
        log (__FILE__, __FUNCTION__, __LINE__, "while lseek'ing to the end of SFX + sizeof(Kbhdr)");
        return false;
    }

    /* write FHT */
    ko.header.k_fhentsize   = sizeof (Fhdr);
    ko.header.k_fhnum       = ko.fht.size();
    write_size = sizeof(Fhdr);
    for (auto fhdr: ko.fht) {
        if (write (ofd, &fhdr, write_size) != write_size) {
            es  = "while writing file header of: ";
            es += &ko.nametab[fhdr.fh_namendx];
            es += "to SFX binary";
            log (__FILE__, __FUNCTION__, __LINE__, es);
            return false;
        }
    }

    /* write archive payload */
    ko.header.k_payloadoff = lseek (ofd, 0, SEEK_CUR);
    if (ko.header.k_payloadoff == -1) {
        log (__FILE__, __FUNCTION__, __LINE__, "while loading ko.header.k_payloadoff (lseek failed)");
        return false;
    }

    uint64_t current_offset = 0;
    for (auto file: ko.payload) {

        write_size = file.size();
        if (write (ofd, &file[0], write_size) != write_size) {
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
    // else 
    //     fprintf (stderr, "Payload successfully written to SFX binary\n");


    /* write names table to file */
    ko.header.k_nametaboff = lseek (ofd, 0, SEEK_CUR);
    if (ko.header.k_nametaboff == -1) {
        log (__FILE__, __FUNCTION__, __LINE__, "while loading ko.header.nametaboff (lseek failed)");
        return false;
    }
    write_size = ko.nametab.size();
    if (write (ofd, &ko.nametab[0], write_size) != write_size) {
        log (__FILE__, __FUNCTION__, __LINE__, "while writing ko.nametab to SFX binary");
        return false;
    }

    /* pwrite kavach binary header @ end of SFX's SHT == kavach_start */
    write_size = sizeof(Kbhdr);
    if (pwrite (ofd, &ko.header, write_size, kavach_start) != write_size) {
         log (__FILE__, __FUNCTION__, __LINE__, "while writing kavach header to SFX binary");
         return false;
    }

    return true;
}
