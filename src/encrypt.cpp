/*
 * Author   : Abhinav Thakur
 * Email    : compilepeace@gmail.com
 * Filename : encrypt.cpp
 *
 * Description: Module responsible for scrambling payload with specific encryption algorithms.
 *              Declared under SCRAMBLE namespace (in kavach.h).
 * 
 * Code Flow: <main> => <pack> => <load_archive_payload> => <encrypt>  
 *
*/

#include "kavach.h"


/* function prototypes */
void pxor (std::vector<uint8_t> &payload, std::string &key);


namespace SCRAMBLE {

    /* encrypts the <payload> using encryption type <etype> and password <key> */
    bool encrypt (std::vector<uint8_t> &payload, std::string &key, Fhdr::encrypt &etype) {

        if (key.length() == 0) {
            log (__FILE__, __FUNCTION__, __LINE__, "encryption key not present, ARCHIVE ONLY mode set");
            return true;
        }

        switch (etype) {
            case Fhdr::encrypt::FET_UND:    
                                            break;
            case Fhdr::encrypt::FET_XOR:    
                                            pxor (payload, key);
                                            break;
            default:
                        fprintf (stderr, "Unknown encryption type\n");
                        break;
        }

        return true;
    }
}
    

/* Payload XOR: xor each byte of <payload> using <key> */
void pxor (std::vector<uint8_t> &payload, std::string &key) {
    
    uint64_t ksize = key.length();

    for (int i = 0; i < payload.size(); ++i) {
        payload[i] = payload[i] ^ key[ i % ksize ];
    }
}