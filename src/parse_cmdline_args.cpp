/********************************************************************************
 * Author   : Abhinav Thakur                                                    *
 * Email    : compilepeace@gmail.com                                            *
 * Filename : parse_cmdline_args.cpp                                            *
 *                                                                              *
 * Description: Module responsible for getting password, target_location        *
 *              and pack_target command line arguments from end user.           *
 *                                                                              *
 * Code Flow: <main> => <parse_cmdline_args>                                    *
 *                                                                              * 
 ********************************************************************************/


#include <getopt.h>

#include "kavach.h"


/* Parse cmd line flags to get information that deceides further program flow */
void parse_cmdline_args (int argc, char **argv, std::string &password_key, std::string &pack_target, std::string &out_filename) {
    
    std::string encryption_type;
    static struct option long_options[] = {
        {"pack",            required_argument,  NULL,   'p'},
        {"unpack",          no_argument,        NULL,   'u'},
        {"key",             required_argument,  NULL,   'k'},
        {"output",          required_argument,  NULL,   'o'},
        {"encrypt",         required_argument,  NULL,   'e'},
        {"help",            no_argument,        NULL,   'h'},
        {"destroy-relics",  no_argument,        NULL,   'd'},
        {0, 0, 0, 0}
    };
    int flag = 0;

    if (argc < 2) {
        print_usage ();
        exit (-1);
    }

    while ( (flag = getopt_long (argc, argv, "de:hk:o:p:u:", long_options, nullptr)) != -1) {
    
        switch (flag) {

            case 'd':   /* --destroy-relics */
                        DESTROY_RELICS = 1;
                        break;

            case 'p':   /* --pack */
                        pack_target = optarg;
                        if (!pack_target.empty())
                            PACK_FLAG   = 1;
                        break;

            case 'k':   /* --key */
                        password_key = optarg;
                        if (!password_key.empty())
                            KEY_FLAG = 1;
                        break;

            case 'u':   /* --unpack */
                        UNPACK_FLAG = 1;
                        break;

            case 'o':   /* --output */
                        out_filename = optarg;
                        if (!out_filename.empty()) 
                            OFNAME_FLAG = 1;
                        break;

            case 'e':   /* --encrypt */
                        encryption_type = optarg;
                        if (encryption_type == "xor") {
                            ENCRYPTION_TYPE = Fhdr::encrypt::FET_XOR;
                        }
                        else {
                            ENCRYPTION_TYPE = Fhdr::encrypt::FET_UND;
                        }
                        break;

            case 'h':   /* --help */
                        print_usage (); 
                        break;

            case '?':   /* no such option */            
            case ':':   /* missing argument for option */
            default :
                        print_usage ();
                        break;
        }
    }
}


void print_usage () {

    std::cout << "\n" BOLDRED
              << "[-]" BOLDCYAN
              << " Usage: " BOLDGREEN "kavach " BOLDWHITE "[-p <target> | -u] -k <key> [-dh]\n\t" RESET
	          << BOLDBLUE "-u" RESET " | " BOLDBLUE "--unpack                           " RESET ":" DIM YELLOW " unpack the data content from invoked SFX\n\t" RESET
              << BOLDBLUE "-p" RESET " | " BOLDBLUE "--pack    <target_location>        " RESET ":" DIM YELLOW " pack target @ (dir|file) location\n\t" RESET
              << BOLDBLUE "-d" RESET " | " BOLDBLUE "--destroy-relics                   " RESET ":" DIM YELLOW " delete all files after packing into kavach generated SFX binary\n\t" RESET
              << BOLDBLUE "-o" RESET " | " BOLDBLUE "--output                           " RESET ":" DIM YELLOW " output filename for kavach generated SFX binary\n\t" RESET
              << BOLDBLUE "-e" RESET " | " BOLDBLUE "--encrypt <encrytion_type>         " RESET ":" DIM YELLOW " encrypt the payload before archiving\n\t" RESET
              << BOLDBLUE "-k" RESET " | " BOLDBLUE "--key     <password_key>           " RESET ":" DIM YELLOW " password key to pack|unpack\n\t" RESET
              << BOLDBLUE "-h" RESET " | " BOLDBLUE "--help                             " RESET ":" DIM YELLOW " display help\n\t" RESET
              << "\n" RED 
              << "NOTE" RESET ": By default, kavach doesn't delete the files after packing.\n\n";
    exit (1);
}
