/*
 * Author   : Abhinav Thakur
 * Email    : compilepeace@gmail.com
 * Filename : kavach.cpp
 *
 * Description: Main launcher code for Kavach binary. Kavach generates sfx binar   
 *
*/

#include "kavach.h"

int 		DESTROY_RELICS 		= 0;
int 		UNPACK_FLAG 		= 0;
int			PACK_FLAG			= 0;
int 		KEY_FLAG			= 0;
int 		OFNAME_FLAG 		= 0;
int			ENCRYPTION_TYPE 	= 0;
uint64_t	KAVACH_BINARY_SIZE 	= 0;
std::string es;


/* function prototypes */
bool get_kavach_binary_size (int kfd, uint64_t &KAVACH_BINARY_SIZE);



int main (int argc, char **argv) {
	std::string password_key;
	std::string pack_target;
	std::string destination_dir;
	std::string out_filename;
	int kfd = -1;


	parse_cmdline_args (argc, argv, password_key, pack_target, destination_dir, out_filename);
	//fprintf (stderr, "%s, %s @ %s, out_filename %s\n", password_key.c_str(), pack_target.c_str(), destination_dir.c_str(), out_filename.c_str());


	/* open kavach binary */
	kfd = open (argv[0], O_RDONLY);
	if (kfd == -1) {
		log (__FILE__, __FUNCTION__, __LINE__, "while open'ing kavach binary");
		return 1;
	}

	/* Get actual kavach size (excluding any archived payload size) */
	if (get_kavach_binary_size (kfd, KAVACH_BINARY_SIZE) == false) {
		log (__FILE__, __FUNCTION__, __LINE__, "while setting KAVACH_BINARY_SIZE.");
		return 1;
	}

	if (!KEY_FLAG) {
		/* get secret key interactively if --key flag not set */
		fprintf (stderr, "[-] Please provide the secret key: ");
		getline (std::cin, password_key);
	}


	if ( PACK_FLAG | UNPACK_FLAG ) {
		
		if (PACK_FLAG) {
			/* pack.cpp: pack target */
			if ( pack (kfd, pack_target, password_key, out_filename) == false ) {
				log ( __FILE__, __FUNCTION__, __LINE__, " couldn't pack the given target" );
				exit (0xa);
			}
			fprintf (stderr, BOLDGREEN "[+] " RESET "Packed %s.\n", pack_target.c_str());
		}

		if (UNPACK_FLAG) {
			/* unpack.cpp: extract target */
			if ( unpack (password_key) == false ) {
				log ( __FILE__, __FUNCTION__, __LINE__, " couldn't unpack the given target" );
				exit (0xb);
			}
			fprintf (stderr, BOLDGREEN "[+] " RESET "Unpacked files @ %s.\n", destination_dir.c_str());
		}
	}

	else {
		/* neither pack nor unpack flag is set by parse_cmdline_args() */
		print_usage ();
		return 1;
	}


	close (kfd);
	return 0;	
}


/**************************************************************************** 
 * computes the size of ELF binary by using the below method rather than	*
 * using fstat () to get file attributes -				 					*
 * 																			*
 * 		filesize = sht_offset + (num_entries_in_sht * size_of_each_entry)	*
 * 																			*
 * NOTE: The reason I don't use fstat () is because it will include the		*
 * 		 size of our overall binary (including the archived payload) which	*
 * 		 would impact the portability for packing. 							*
 * 																			*
 * In short, this method ensures that -										*
 * 		"Even an archived SFX can archive new files!"						*
 * 																			*
 ****************************************************************************/
bool get_kavach_binary_size (int kfd, uint64_t &KAVACH_BINARY_SIZE) {
	
	Elf64_Ehdr ehdr;

	if (read (kfd, &ehdr, sizeof (Elf64_Ehdr)) != sizeof (Elf64_Ehdr)) {
		log (__FILE__, __FUNCTION__, __LINE__, "couldn't read elf header");
		return false;
	}

	KAVACH_BINARY_SIZE = ehdr.e_shoff + (ehdr.e_shnum * ehdr.e_shentsize);

	/* set the file pointer back to the beginning of the file */
	if (lseek (kfd, 0, SEEK_SET) != 0) {
		log (__FILE__, __FUNCTION__, __LINE__, "couldn't set the kavach file position back to the beginning");
		return false;
	}

	return true;	
}