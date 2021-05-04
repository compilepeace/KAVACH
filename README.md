# KAVACH
![help](./images/help.png)

Kavach is a free and open source **data protection software**, technically a **self-distributing SFX/SEA** software for Linux whose development was inspired by [Karna]'s armour (from the epic Mahabharat). It is a **SFX** (**SelF eXtractor** or **Self Extracting Archive**) that allows a user to encrypt/archive supplied data with executable code such that ***no system software installation*** is required to unpack the files rather execution of SFX archive alone is enough to pack/unpack user data. The ELF binary packed/archived by kavach code body has an extension of **.kgs** (short for **K**avach **G**enerated **S**FX) along with a **KUNDAL** (indicating a packed binary) in its ELF header (at an offset of 0x8 bytes). Self-distributing here means a single *.kgs archive can be used to create other archives due to its *code body* having a ***self-replicating nature***. In short -

**"If you have a kavach generated archive, you definitely have the software to unpack your content."**

 **NOTE**: Kavach uses a custom binary format termed as KBF (short for **K**avach **B**inary **F**ormat) to zip files either in **plain text (raw unchanged bytes)** or an **encrypted (scrambled senseless bytes)** form.


## KUNDAL (*.kgs)
It has a *custom binary format* responsible for posessing payload and metadata which is made **independently parsable** (made position-independent using relative offsets), i.e. making kavach code and payload mutually-exclusively independent of each other. It tries to **retain** most of the file's metadata while *packing/unpacking* data. Along with the directory structure, it preserves-
* File/Directory **permission bits**.
* Last **access** and last **modification** timestamp.
* KBF is scalable to extend to additional attributes (like **ownership** information) with slight modification.



## CHECK IT OUT !
To use it, you can build kavach from source code by following -

![git_clone](./images/git_clone.png)

### Build
To build, leverage the `make` utility.

![build](./images/build.png)

### Pack
By default, kavach runs in *archive only* mode. Using `--encrypt` flag allows us to specify an encryption routine to scramble sensitive data. Let's look at the target directory tree to archive named *testme*.

![target](./images/target.png)

To pack this directory tree, invoke the program and pass relevant flags as below - 
```
compilepeace@d3ad:~/KAVACH$ ./bin/kavach --pack "./testme" --output karna --encrypt xor --key "Am I an evil" --destroy-relics
```

![pack](./images/pack.png)

**NOTE**: Kavach can be scaled upto the target's component-level encryption (i.e. different encryption routine with a same/different key for every file to be archived). Even the filenames can be encrypted with slight modifications as KBF has a seperate **names table** which centerally stores all name strings.

### Packed artifacts

![metadata](./images/metadata.png)

We see a binary named `karna.kgs`, i.e. the generated SFX. A kavach **packed** SFX (\*.kgs) can be identified by the signature - **KUNDAL** that is present inside the padding of ELF header (starting @ offset 0xa). All .kgs binaries have a special section named `.kavach` which accounts for the entire KBF (Kavach Binary Format).


### Unpack
```
compilepeace@d3ad:~/KAVACH$ ./karna.kgs --unpack karna.kgs --key "Am I an evil"
```

![unpack](./images/unpack.png)

By default, the payload is unpacked in a directory named \<packed_filename\>_dir.

![unpack_dir](./images/unpack_dir.png)


*Kavach* indeed refers to the code body either of the **originally compiled kavach software** or any generated **\*.kgs** binary both of which will act as original kavach software.

## CONTRIBUTIONS
Kavach strongly needs contribution in the encryption module before it can become usable. Currently, XOR-encryption is naively applied to the payload body if the input files constitute any 0 bytes; compromising the integrity provided to the end user. Feel free to reach me out if you would like to contribute to this project.

Cheers,
<br>

[Karna]: https://en.wikipedia.org/wiki/Karna


**NAME**  : Abhinav Thakur <br>
**EMAIL** : compilepeace@gmail.com  
