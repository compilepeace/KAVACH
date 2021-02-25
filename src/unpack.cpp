/********************************************************************************
 * Author   : Abhinav Thakur                                                    *
 * Email    : compilepeace@gmail.com                                            *
 * Filename : unpack.cpp                                                        *
 *                                                                              *
 * Description: Module responsible for self extracting target files from        *
 *              its own body.                                                   *
 *                                                                              *
 * Code Flow: <main> => <unpack>                                                *
 *                                                                              * 
 ********************************************************************************/

#include "kavach.h"


/* function prototypes */
static bool is_packed           (int kfd);
static bool extract             (uint8_t *map, int entry_dirfd, std::string &key);
static bool _extract            (uint8_t *map, Kbhdr *header, uint8_t *nametab, uint8_t *payload, std::string &key, Fhdr *fht, uint64_t i, std::stack<int> &dirfds);


/* Entry point to unpacking SFX binary */
bool unpack (int sfxfd, std::string &target_location, std::string &key) {

    struct stat sfxsb;
    uint8_t     *map;
    uint64_t    map_offset;
    uint64_t    remainder;
    std::string out_archive;
    int         entry_dirfd;


    /* Verify that I am a packed binary */
    if (is_packed (sfxfd) == false) {
        log (__FILE__, __FUNCTION__, __LINE__, "this program is not a packed kavach binary");
        return false;
    }

    if ( fstat(sfxfd, &sfxsb) == -1) {
        log (__FILE__, __FUNCTION__, __LINE__, "while fstat'ing SFX binary");
        return false;
    }

    /* mmap kavach binary format. Offset to mmap must be a multiple of PAGE_SIZE. */
    remainder   = (KAVACH_BINARY_SIZE % PAGE_SIZE);
    map_offset  = KAVACH_BINARY_SIZE - remainder;

    map = (uint8_t *) mmap (NULL, sfxsb.st_size - map_offset, PROT_READ, MAP_SHARED, sfxfd, map_offset);
    if (map == MAP_FAILED) {
        log (__FILE__, __FUNCTION__, __LINE__, "while mmap'ing kavach binary format");
        return false;
    }

    /* create a directory by the name of packed binary (target_location) */
    out_archive = target_location.substr(0, target_location.find("."));
    out_archive += "_dir";
    if (mkdir (out_archive.c_str(), S_IRWXU | S_IRWXG | S_IRWXO) == -1) {
        es = "while creating " + out_archive + " directory";
        log (__FILE__, __FUNCTION__, __LINE__, es);
        return false;
    }

    /* open up output directory */
    entry_dirfd = open (out_archive.c_str(), O_RDONLY);
    if ( entry_dirfd == -1) {
        es = "while opening " + out_archive;
        log (__FILE__, __FUNCTION__, __LINE__, es);
        return false;
    }

    /* parse kavach binary format */
    extract (map + remainder, entry_dirfd, key);


    close (entry_dirfd);
    return true;
}



/* Parse Kavach object and extract the payload in directory represented by entry_dirfd */
static bool extract (uint8_t *map, int entry_dirfd, std::string &key) {

    Kbhdr               *header  = (Kbhdr *)   map;
    Fhdr                *fht     = (Fhdr *)    &map[header->k_fhtoff];
    uint8_t             *payload = (uint8_t *) &map[header->k_payloadoff];
    uint8_t             *nametab = (uint8_t *) &map[header->k_nametaboff]; 
    std::stack<int>     dirfds;

    /* parse FHT recursively starting from 0th entry and extract each entry *
     * Also, initialize dirfds stack with entry point directory fd          */
    dirfds.push (entry_dirfd);
    if ( _extract (map, header, nametab, payload, key, fht, 0, dirfds) == false ) {
        log (__FILE__, __FUNCTION__, __LINE__, "while extracting payload");
        return false;
    }
    dirfds.pop ();          /* pop entry_dirfd */
    
    if (!dirfds.empty()) {
        log (__FILE__, __FUNCTION__, __LINE__, "dirfds stack is not yet empty");
        return false;
    }

    return true;
}



/****************************************************************************
 * Parse FHT recursively to create an unpacked directory tree.              *
 * NOTE: To create a directory tree, we leverage a stack of directory file  *
 *       descriptors <dirfds> and empty Fhdr entries in FHT.                *
 *       dirfds.top() always gets the file descriptor of the directory in   *
 *       which the files are currently being extracted.                     *
 *       A NULL FHT entry marks as the EOD (End Of Directory contents).     *
 ****************************************************************************/
static bool _extract ( uint8_t *map, Kbhdr *header, uint8_t *nametab, uint8_t *payload,
                      std::string &key, Fhdr *fht, uint64_t i, std::stack<int> &dirfds) {

    std::vector<uint8_t>    d_payload;      /* payload to decrypt */                                
    std::string             name;
    bool                    status;
    int                     fd;
    

    if (i >= header->k_fhnum) {
        return true;
    }

    switch (fht[i].fh_ftype)
    {
        case Fhdr::ftype::FT_FILE:  
                                    /* decrypt and dump to disk */

                                    /* create a file */
                                    name = (char *) &nametab[fht[i].fh_namendx];
                                    fd = openat ( dirfds.top(), name.c_str(), O_CREAT|O_WRONLY, fht[i].fh_mode);
                                    if (fd == -1) {
                                        es = "while creating file named: " + name ;
                                        log (__FILE__, __FUNCTION__, __LINE__, es);
                                        return false;
                                    }

                                    /* write its saved last access and modification time */
                                    if ( futimens (fd, fht[i].fh_time) == -1) {
                                        es = "while writing saved timestamps for: " + name;
                                        log (__FILE__, __FUNCTION__, __LINE__, es);
                                        return false;
                                    }

                                    /* move the payload into d_payload vector (of raw bytes) */
                                    d_payload.resize(fht[i].fh_size);
                                    memmove (&d_payload[0], &map[header->k_payloadoff + fht[i].fh_offset], fht[i].fh_size);

                                    /* check if it is encrypted */
                                    if (fht[i].fh_etype != Fhdr::encrypt::FET_UND) {
                                        
                                        if ( KEY_FLAG && !key.empty() ) {
                                            /* decrypt if encrypted */
                                            if ( DESCRAMBLE::decrypt (d_payload, key, fht[i].fh_etype) == false) {
                                                es = "while decrypting payload for: " + name;
                                                log (__FILE__, __FUNCTION__, __LINE__, es);
                                            }
                                        }
                                        
                                        else {
                                            es = "decryption key not supplied for: " + name;
                                            log (__FILE__, __FUNCTION__, __LINE__, es);
                                            return false;
                                        }

                                    }

                                    /* write d_payload bytes to file */
                                    if (write (fd, &d_payload[0], d_payload.size()) != d_payload.size()) {
                                        es = "while writing payload to file: " + name;
                                        log (__FILE__, __FUNCTION__, __LINE__, es);
                                        return false;
                                    }

                                    /* save the created file and extract next file header */
                                    close (fd);                 
                                    status = _extract (map, header, nametab, payload, key, fht, i + 1, dirfds); 
                                    break;

        case Fhdr::ftype::FT_DIR:   
                                    /* create a directory and append its name to path */
                                    name = (char *) &nametab[fht[i].fh_namendx];
                                    if (mkdirat (dirfds.top(), name.c_str(), fht[i].fh_mode) == -1) {
                                        es = "while creating directory: " + name;
                                        log (__FILE__, __FUNCTION__, __LINE__, es);
                                        return false;
                                    }

                                    fd = openat (dirfds.top(), name.c_str(), O_RDONLY);
                                    if (fd == -1) {
                                        es = "while opening newly created directory: " + name ;
                                        log (__FILE__, __FUNCTION__, __LINE__, es);
                                        return false;
                                    }

                                    /* write its saved last access and modification time */
                                    if ( futimens (fd, fht[i].fh_time) == -1) {
                                        es = "while writing saved timestamps for directory: " + name;
                                        log (__FILE__, __FUNCTION__, __LINE__, es);
                                        return false;
                                    }

                                    /* push the current directory file descriptor to dirfds stack */
                                    dirfds.push (fd);

                                    /* extract next file header */
                                    status = _extract (map, header, nametab, payload, key, fht, i + 1, dirfds);
                                    close (fd);
                                    break;

        case Fhdr::ftype::FT_UND:   
                                    /* A NULL fhdr entry, meaning return to previous path */
                                    dirfds.pop();
                                    status = _extract (map, header, nametab, payload, key, fht, i + 1, dirfds);
                                    break;

        default:
                    log (__FILE__, __FUNCTION__, __LINE__, "no such file type (while parsing FHT)");
                    return false;
    }
    
    return status;
}



/* Identify packed binary by checking for SIGNATURE */
static bool is_packed (int sfxfd) {

    uint64_t signature = 0;

    if ( pread (sfxfd, &signature, 0x8, 0x8) != 0x8 ||
         signature != PACK_SIGNATURE ) {     
        log (__FILE__, __FUNCTION__, __LINE__, "current SFX binary doesn't contain KUNDAL");
        return false;
    }

    return true;
}