/*
 * Author   : Abhinav Thakur
 * Email    : compilepeace@gmail.com
 * Filename : parse_cmdline_args.cpp
 *
 * Description: Module responsible for getting password, unpack_target
 *              and pack_target command line arguments from end user.
 * 
 * Code Flow: <main> => <parse_cmdline_args>   
 *
*/


#include <getopt.h>

#include "kavach.h"


/* Parse cmd line flags to get information that deceides further program flow */
void parse_cmdline_args (int argc, char **argv, std::string &password_key, std::string &pack_target, std::string &destination_dir, std::string &out_filename) {
    
    std::string encryption_type;
    static struct option long_options[] = {
        {"pack",            required_argument,  NULL,   'p'},
        {"unpack",          required_argument,  NULL,   'u'},
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
                        destination_dir = optarg;
                        if (!destination_dir.empty())
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
                            ENCRYPTION_TYPE = E_TYPE_XOR;
                        }
                        else {
                            ENCRYPTION_TYPE = E_TYPE_NONE;
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

    std::cout << "\n[-] Usage: kavach [-p <target> | -u <target>] -k <key> [-dh]\n"
              << "\t-p | --pack   <target_location>         : pack target @ (dir|file) location\n"
              << "\t-d | --destroy-relics                   : delete all files after packing into kavach generated SFX binary\n"
              << "\t-o | --output                           : output filename for kavach generated SFX binary\n"
              << "\t-u | --unpack <destination_directory>   : unpack the data content @ destination_directory\n"
              << "\t-k | --key    <password_key>            : password key to pack|unpack\n"
              << "\t-h | --help                             : display help\n"
              << "\nNOTE: By default, kavach doesn't delete the files after packing.\n\n";
    exit (1);
}