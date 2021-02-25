/********************************************************************************
 * Author   : Abhinav Thakur                                                    *
 * Email    : compilepeace@gmail.com                                            *
 * Filename : decrypt.cpp                                                       *
 *                                                                              *
 * Description: Module responsible for descrambling payload with respective     *
 *              decryption algorithms.                                          *
 *              Declared under DESCRAMBLE namespace (in kavach.h).              *
 *                                                                              *
 * Code Flow: <main> => <unpack> => <extract> => <decrypt>                      *
 *                                                                              * 
 ********************************************************************************/

#include "kavach.h"


/* function prototypes */


namespace DESCRAMBLE {

    /* decrypts the <payload> for encryption type <etype> with password <key> */
    bool decrypt (std::vector<uint8_t> &payload, std::string &key, Fhdr::encrypt &etype) {

        if (key.length() == 0) {
            log (__FILE__, __FUNCTION__, __LINE__, "decryption key not present, ARCHIVE ONLY mode set");
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