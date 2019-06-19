/*
    UOHC (Ultima Online (UOP) Hash Cracker) by Nolok.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

/* Compilation tips
    (When using visual studio, you need to set this preprocessor macro: _CRT_SECURE_NO_WARNINGS)

    Enable every possible optimization (remember omit frame pointer) and disable every possible additional compiler security check.
     In particular, when using Visual Studio, disable C++ exceptions, safety checks (/Gs-), SDL checks (/sdl-), Control Flow Guard (/GUARD:NO).
     Having them enabled makes the code slower, and you don't want that for a brute-force attack :)

    Enable parallelization using OpenMP:
     you need to add the option -fopenmp to gcc, /openmp to cl (visual C++ compiler) or -openmp-stubs to ICC (intel C compiler)
*/

// For testing purposes: Hash=(0x)280F5FD7008898E6 | prefix=build/gumpartlegacymul/ | suffix=.tga | min_len=1 | max_len=8 | charset=0123456789 | result = build/gumpartlegacymul/00001283.tga


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <signal.h>
#include <time.h>

/*
#if defined (_WIN32)
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
#elif defined (__linux__) || defined (__APPLE__) || defined (UNIX)
    #include <unistd.h>
    #include <sys/sysinfo.h>
#endif
*/

#ifdef _WIN32
    #include <malloc.h>
    #ifdef _MSC_VER
        #define alloca _alloca
    #endif
#else
    #include <alloca.h>
#endif


//Size for the char array containing input (before transferring it into different variables)
#define MAX_ARG_LEN 60

#if defined (_OPENMP)
    #define PARALLELIZATION 1
#else
    #define PARALLELIZATION 0
#endif

typedef unsigned long long ullong;


/*	Global Vars	*/

// values will be assigned in the main function; they are accessed by multiple functions
ullong hash = 0; // the return value of the hash function is actually a uint64_t, but i like the compiler to know that also a non fixed-size type will do
unsigned int filename_minlen = 0;
unsigned int filename_maxlen = 0;
char* prefix = NULL;
char* suffix = NULL;
char* charset = NULL;

// values assigned in the main function, after processing the values of the variables above
unsigned int prefix_len;
unsigned int suffix_len;
unsigned int charset_len;
unsigned int key_maxlen;

// to manage the process
int working = 0;
int stop = 0;
char* key;			//for the matching (cracked) string (prefix+filename+suffix)


/* Handler for CTRL + C */

void sig_handler(int signo)
{
    if (working)
        stop = 1;
}


/* Self explanatory */

void pre_exit(int force)
{
    printf("\nPress a key to exit.");
    getchar();

    if (force)
        exit(1);
}


/* Hash function */

//This is a slightly optimized adaptation of the C# algorithm by Malganis, which is included in Mythic Package Editor sources
static inline ullong hashcalc(
    const char* str,
    const unsigned int concatenated_len,// pre calculated length of str
    const uint32_t hash_magic           // pre calculated magic value, dependant on the length of str
)
{
    uint32_t eax, ecx, edx, ebx, esi, edi;

    eax = ecx = edx = 0;
    ebx = edi = esi = hash_magic;
    //ebx = edi = esi = (uint32_t)concatenated_len + 0xDEADBEEF;

    unsigned int i, diff;

    for (i = 0; i + 12 < concatenated_len; i += 12)
    {
        edi = (uint32_t)((str[i + 7] << 24) | (str[i + 6] << 16) | (str[i + 5] << 8) | str[i + 4]) + edi;
        esi = (uint32_t)((str[i + 11] << 24) | (str[i + 10] << 16) | (str[i + 9] << 8) | str[i + 8]) + esi;
        edx = (uint32_t)((str[i + 3] << 24) | (str[i + 2] << 16) | (str[i + 1] << 8) | str[i]) - esi;

        edx = (edx + ebx) ^ (esi >> 28) ^ (esi << 4);
        esi += edi;
        edi = (edi - edx) ^ (edx >> 26) ^ (edx << 6);
        edx += esi;
        esi = (esi - edi) ^ (edi >> 24) ^ (edi << 8);
        edi += edx;
        ebx = (edx - esi) ^ (esi >> 16) ^ (esi << 16);
        esi += edi;
        edi = (edi - ebx) ^ (ebx >> 13) ^ (ebx << 19);
        ebx += esi;
        esi = (esi - edi) ^ (edi >> 28) ^ (edi << 4);
        edi += ebx;
    }

    diff = (concatenated_len - i);
    if (diff > 0)
    {
        if (diff == 12)
        {
            esi += (uint32_t)str[i + 11] << 24;
            esi += (uint32_t)str[i + 10] << 16;
            esi += (uint32_t)str[i + 9] << 8;
            esi += (uint32_t)str[i + 8];
            edi += (uint32_t)str[i + 7] << 24;
            edi += (uint32_t)str[i + 6] << 16;
            edi += (uint32_t)str[i + 5] << 8;
            edi += (uint32_t)str[i + 4];
            ebx += (uint32_t)str[i + 3] << 24;
            ebx += (uint32_t)str[i + 2] << 16;
            ebx += (uint32_t)str[i + 1] << 8;
            ebx += (uint32_t)str[i];
        }
        else if (diff == 11)
        {
            esi += (uint32_t)str[i + 10] << 16;
            esi += (uint32_t)str[i + 9] << 8;
            esi += (uint32_t)str[i + 8];
            edi += (uint32_t)str[i + 7] << 24;
            edi += (uint32_t)str[i + 6] << 16;
            edi += (uint32_t)str[i + 5] << 8;
            edi += (uint32_t)str[i + 4];
            ebx += (uint32_t)str[i + 3] << 24;
            ebx += (uint32_t)str[i + 2] << 16;
            ebx += (uint32_t)str[i + 1] << 8;
            ebx += (uint32_t)str[i];
        }
        else if (diff == 10)
        {
            esi += (uint32_t)str[i + 9] << 8;
            esi += (uint32_t)str[i + 8];
            edi += (uint32_t)str[i + 7] << 24;
            edi += (uint32_t)str[i + 6] << 16;
            edi += (uint32_t)str[i + 5] << 8;
            edi += (uint32_t)str[i + 4];
            ebx += (uint32_t)str[i + 3] << 24;
            ebx += (uint32_t)str[i + 2] << 16;
            ebx += (uint32_t)str[i + 1] << 8;
            ebx += (uint32_t)str[i];
        }
        else if (diff == 9)
        {
            esi += (uint32_t)str[i + 8];
            edi += (uint32_t)str[i + 7] << 24;
            edi += (uint32_t)str[i + 6] << 16;
            edi += (uint32_t)str[i + 5] << 8;
            edi += (uint32_t)str[i + 4];
            ebx += (uint32_t)str[i + 3] << 24;
            ebx += (uint32_t)str[i + 2] << 16;
            ebx += (uint32_t)str[i + 1] << 8;
            ebx += (uint32_t)str[i];
        }
        else if (diff == 8)
        {
            edi += (uint32_t)str[i + 7] << 24;
            edi += (uint32_t)str[i + 6] << 16;
            edi += (uint32_t)str[i + 5] << 8;
            edi += (uint32_t)str[i + 4];
            ebx += (uint32_t)str[i + 3] << 24;
            ebx += (uint32_t)str[i + 2] << 16;
            ebx += (uint32_t)str[i + 1] << 8;
            ebx += (uint32_t)str[i];
        }
        else if (diff == 7)
        {
            edi += (uint32_t)str[i + 6] << 16;
            edi += (uint32_t)str[i + 5] << 8;
            edi += (uint32_t)str[i + 4];
            ebx += (uint32_t)str[i + 3] << 24;
            ebx += (uint32_t)str[i + 2] << 16;
            ebx += (uint32_t)str[i + 1] << 8;
            ebx += (uint32_t)str[i];
        }
        else if (diff == 6)
        {
            edi += (uint32_t)str[i + 5] << 8;
            edi += (uint32_t)str[i + 4];
            ebx += (uint32_t)str[i + 3] << 24;
            ebx += (uint32_t)str[i + 2] << 16;
            ebx += (uint32_t)str[i + 1] << 8;
            ebx += (uint32_t)str[i];
        }
        else if (diff == 5)
        {
            edi += (uint32_t)str[i + 4];
            ebx += (uint32_t)str[i + 3] << 24;
            ebx += (uint32_t)str[i + 2] << 16;
            ebx += (uint32_t)str[i + 1] << 8;
            ebx += (uint32_t)str[i];
        }
        else if (diff == 4)
        {
            ebx += (uint32_t)str[i + 3] << 24;
            ebx += (uint32_t)str[i + 2] << 16;
            ebx += (uint32_t)str[i + 1] << 8;
            ebx += (uint32_t)str[i];
        }
        else if (diff == 3)
        {
            ebx += (uint32_t)str[i + 2] << 16;
            ebx += (uint32_t)str[i + 1] << 8;
            ebx += (uint32_t)str[i];
        }
        else if (diff == 2)
        {
            ebx += (uint32_t)str[i + 1] << 8;
            ebx += (uint32_t)str[i];
        }
        else if (diff == 1)
        {
            ebx += (uint32_t)str[i];
        }

        esi = (esi ^ edi) - ((edi >> 18) ^ (edi << 14));
        ecx = (esi ^ ebx) - ((esi >> 21) ^ (esi << 11));
        edi = (edi ^ ecx) - ((ecx >> 7) ^ (ecx << 25));
        esi = (esi ^ edi) - ((edi >> 16) ^ (edi << 16));
        edx = (esi ^ ecx) - ((esi >> 28) ^ (esi << 4));
        edi = (edi ^ edx) - ((edx >> 18) ^ (edx << 14));
        eax = (esi ^ edi) - ((edi >> 8) ^ (edi << 24));

        return ((uint64_t)edi << 32) | eax;
    }

    return ((uint64_t)esi << 32) | eax;
}


/* Cracking algorithm */

static void crack_seed_range(
    const unsigned int generated_len,
    const ullong seed_len_first,
    const ullong seed_len_slast
)
{
    unsigned int concatenated_len;   //length of the strings generated for this cycle, concatenated to prefix and suffix
    concatenated_len = prefix_len + generated_len + suffix_len;

    #pragma omp parallel shared(stop) if (PARALLELIZATION)
    {
        /* initialize the arrays that will contain the generated and the concatenated string */

        // alloca allocates the memory on the stack (accessing that memory is way faster than the one allocated on the heap),
        //  and the memory is freed automatically when the function exits (not when the variable goes out of scope, also the call to free isn't needed)
        char * const concatenated = alloca((concatenated_len + 1) * sizeof(char));
        memcpy(concatenated, prefix, prefix_len);
        memcpy(concatenated + prefix_len + generated_len, suffix, suffix_len);
        *(concatenated + concatenated_len) = '\0';

        // where to start placing the generated characters in the pre-concatenated string
        char * const generate_offset = concatenated + prefix_len;

        const char * const local_charset = alloca((charset_len + 1) * sizeof(char));
        memcpy((char*)local_charset, charset, (charset_len + 1) * sizeof(char));

        // prepare this value for hash function; it's convenient to do this operation once for
        //	each group of strings of fixed length, instead of at each function call
        const uint32_t hash_magic = (uint32_t)concatenated_len + 0xDEADBEEF;

        // store in contiguous memory once this stuff (faster access, less assembly instructions and memory reads)
        const ullong local_hash = hash;
        const unsigned int local_charset_len = charset_len;


        /* Generate the strings */

        if (seed_len_slast <= UINT_MAX)
        {
            // no need to use 64 bits registers and operations if we know that 32 bits one will suffice (for the current max seed)
            //  (performance improvement is real)
            const unsigned int uint_seed_len_slast = (unsigned int)seed_len_slast;
            unsigned int seed;
            #pragma omp for schedule(static) private(seed)
            for (seed = (unsigned int)seed_len_first; seed < uint_seed_len_slast; ++seed)
            {
#if defined(PARALLELIZATION)
                if (!stop)	// need to check if we have finished by this way because of OpenMP
#endif
                {
                    /* generate the string from the seed */
                    unsigned int seed_p = seed;
                    for (unsigned int pos = 0; pos < generated_len; ++pos)
                    {
                        *(generate_offset + pos) = local_charset[seed_p % local_charset_len];
                        seed_p /= local_charset_len;
                    }

                    /* check if the hashed string matches the hash we are cracking */
                    if (hashcalc(concatenated, concatenated_len, hash_magic) == local_hash)
                    {
                        #pragma omp critical
                        {
                            stop = 1;
                            strcpy(key, concatenated);
                        }
#if !defined(PARALLELIZATION)
                        return;
#endif
                    }
                }
            }
        }
        else
        {
            ullong seed;
            #pragma omp for schedule(static) private(seed)
            for (seed = seed_len_first; seed < seed_len_slast; ++seed)
            {
#if defined(PARALLELIZATION)
                if (!stop)	// need to check if we have finished by this way because of OpenMP
#endif
                {
                    /* generate the string from the seed */
                    ullong seed_p = seed;
                    for (unsigned int pos = 0; pos < generated_len; ++pos)
                    {
                        *(generate_offset + pos) = local_charset[seed_p % local_charset_len];
                        seed_p /= local_charset_len;
                    }

                    /* check if the hashed string matches the hash we are cracking */
                    if (hashcalc(concatenated, concatenated_len, hash_magic) == local_hash)
                    {
                        #pragma omp critical
                        {
                            stop = 1;
                            strcpy(key, concatenated);
                        }
#if !defined(PARALLELIZATION)
                        return;
#endif
                    }
                }
            }
        }
    }
}


/* Custom power function */

static inline ullong my_pow(const unsigned int base, const unsigned int exp) //meant only for positive integers
{
    if (exp == 0)
        return 1;
    ullong res = base;
    for (unsigned int x = 1; x < exp; ++x)
        res *= base;
    return res;
}


/* Core */

static void start_crack()
{
    working = 1;

    /*	Initializing  */

    printf("\nIf you want to abort computation, press CTRL + C.");
    printf("\nInitializing...");

    //note: as said, strlen doesn't count the terminator '\0', which in this case is fine
    key_maxlen = prefix_len + filename_maxlen + suffix_len + 1;	//+1 for the "\0" terminator
    key = calloc (key_maxlen, sizeof(char)); //using calloc because it's good to have the vars 0 initialized

    // number of maximum combinations we can get with length = filename_maxlen
    ullong combinations_max = 0;
    // array containing the number of maximum combinations for each output string length
    ullong* combinations_len;     //index starts from 1, not from 0
    combinations_len = malloc((filename_maxlen + 1) * sizeof(ullong));


    /* Loop that generates and checks strings of increasing length */

    time_t t;   //for time tracking
    for (unsigned int generated_len = 1; generated_len <= filename_maxlen; ++generated_len)
    {
        const ullong tmp_combinations_max = combinations_max;
        combinations_max += my_pow(charset_len, generated_len);
        if (combinations_max < tmp_combinations_max)
        {
            // overflow
            printf("\nFATAL: The combinations to generate will be so many that the internal algorithm will break.");
            printf("\n Try with a smaller charset or length.");
            pre_exit(1);
        }

        combinations_len[generated_len] = combinations_max;
    }
    combinations_len[0] = 0;

    printf("\nStarting...\n");
    working = 1;


    /* Start generating strings */

    unsigned int generated_len; //length of the strings generated for this cycle
    ullong seed_len_first;      //first seed generating a string of length "generated_len"
    ullong seed_len_slast;      //second last (penultimate) seed generating a string of length "generated_len"
    //ullong seed = 0;          //seed from which the string is generated; seed determine both length and characters
    for (generated_len = filename_minlen; (generated_len <= filename_maxlen) && !stop; ++generated_len)
    {
        seed_len_first = combinations_len[generated_len - 1];
        seed_len_slast = combinations_len[generated_len];
        time(&t);
        printf("Checking passwords width [ %d ]...   Started: %s", generated_len, asctime(localtime(&t)));

        crack_seed_range(generated_len, seed_len_first, seed_len_slast);
    }

    time(&t);
    printf("Ended: %s", asctime(localtime(&t)));

    free(combinations_len);
    working = 0;
}


/* Main function, here happens most of the stuff */

int main()
{
    printf("UOHC: Ultima Online UOP Hash Cracker.");
    printf("\nv2.0.1 CPU PARALLEL algorithm.");
#if (PARALLELIZATION)
    printf("\nCompiled with OpenMP support (multi-threaded): on a decent multi-core cpu is faster than SERIAL algorithm.");
#else
    printf("\nCompiled WITHOUT OpenMP support (single-threaded, always slower than serial).");
#endif


    /*	Enable handling CTRL + C */

    if (signal(SIGINT, sig_handler) == SIG_ERR)
        printf("\n\nWarning: Can't catch SIGINT. If you want to stop the program you have to close it manually.\n");

    char another_hash = 0;  //stores the answer when asked for cracking another hash
    char* buf = calloc(MAX_ARG_LEN, sizeof(char));		//initialize buffer for storing inserted parameters

    while (1)
    {
        /*	Collecting parameters	*/

        if (!another_hash)	//if data is inserted for the first time
        {
            printf("\n\nInsert data (max argument length: %d, empty parameters are not accepted)", MAX_ARG_LEN);
            printf("\nHash: 0x");
            do
            {
                fgets(buf, MAX_ARG_LEN, stdin);
            } while (*buf == '\n');				//avoid taking empty argument (string should be {'\n','\0'})
            hash = strtoull(buf, NULL, 16);		//convert the string into a base 16 (hexadecimal) unsigned long long
        }
        else
        {
            printf("\n\nInsert data (max argument length: %d) [default in brackets] ", MAX_ARG_LEN);
            printf("\nTo enter default value, just leave it empty and press enter");
            printf("\nHash [0x%" PRIx64 "]: 0x", hash);
            fgets(buf, MAX_ARG_LEN, stdin);
            if (*buf != '\n')						//if i send only newline (enter), don't store the value
                hash = strtoull(buf, NULL, 16);
        }
        memset(buf, '\0', MAX_ARG_LEN * sizeof(char));

        if (!another_hash)
        {
            printf("Generated filename minimum length: ");
            do
            {
                fgets(buf, MAX_ARG_LEN, stdin);
            } while (*buf == '\n');
            filename_minlen = (unsigned int)strtoul(buf, NULL, 0);
            if (filename_minlen == 0)
                filename_minlen = 1;
        }
        else
        {
            printf("Generated filename minimum length [%d]: ", filename_minlen);
            fgets(buf, MAX_ARG_LEN, stdin);
            if (*buf != '\n')
                filename_minlen = (unsigned int)strtoul(buf, NULL, 0);
        }
        memset(buf, '\0', MAX_ARG_LEN * sizeof(char));

        if (!another_hash)
        {
            printf("Generated filename maximum length: ");
            do
            {
                fgets(buf, MAX_ARG_LEN, stdin);
            } while (*buf == '\n');
            filename_maxlen = (unsigned int)strtoul(buf, NULL, 0);
            if (filename_maxlen == 0)
                filename_maxlen = 1;
        }
        else
        {
            printf("Generated filename maximum length [%d]: ", filename_maxlen);
            fgets(buf, MAX_ARG_LEN, stdin);
            if (*buf != '\n')
                filename_maxlen = (unsigned int)strtoul(buf, NULL, 0);
        }
        memset(buf, '\0', MAX_ARG_LEN * sizeof(char));

        if (!another_hash)
        {
            printf("Charset: ");
            do
            {
                fgets(buf, MAX_ARG_LEN, stdin);
            } while (*buf == '\n');
            charset = malloc(strlen(buf) * sizeof(char));		//strlen counts \n, which i overwrite with \0, the string terminator character
            strcpy(charset, buf);
            charset_len = (unsigned)(strlen(charset) - 1);
        }
        else
        {
            printf("Charset [%s]: ", charset);
            fgets(buf, MAX_ARG_LEN, stdin);
            if (*buf != '\n')
            {
                charset = realloc(charset, strlen(buf) * sizeof(char));
                strcpy(charset, buf);
                charset_len = (unsigned)(strlen(charset) - 1);
            }
        }
        charset[charset_len] = '\0';
        memset(buf, '\0', MAX_ARG_LEN * sizeof(char));

        if (!another_hash)
        {
            printf("Prefix: ");
            do
            {
                fgets(buf, MAX_ARG_LEN, stdin);
            } while (*buf == '\n');
            prefix = malloc(strlen(buf) * sizeof(char));
            strcpy(prefix, buf);
            prefix_len = (unsigned)(strlen(prefix) - 1);
        }
        else
        {
            printf("Prefix [%s]: ", prefix);
            fgets(buf, MAX_ARG_LEN, stdin);
            if (*buf != '\n')
            {
                prefix = realloc(prefix, strlen(buf) * sizeof(char));
                strcpy(prefix, buf);
                prefix_len = (unsigned)(strlen(prefix) - 1);
            }
        }
        prefix[prefix_len] = '\0';
        memset(buf, '\0', MAX_ARG_LEN * sizeof(char));

        if (!another_hash)
        {
            printf("Suffix: ");
            do
            {
                fgets(buf, MAX_ARG_LEN, stdin);
            } while (*buf == '\n');
            suffix = malloc(strlen(buf) * sizeof(char));
            strcpy(suffix, buf);
            suffix_len = (unsigned)(strlen(suffix) - 1);
        }
        else
        {
            printf("Suffix [%s]: ", suffix);
            fgets(buf, MAX_ARG_LEN, stdin);
            if (*buf != '\n')
            {
                suffix = realloc(suffix, strlen(buf) * sizeof(char));
                strcpy(suffix, buf);
                suffix_len = (unsigned)(strlen(suffix) - 1);
            }
        }
        suffix[suffix_len] = '\0';
        memset(buf, '\0', MAX_ARG_LEN * sizeof(char));


        /*	Move to actual cracking code */

        start_crack();


        /*	End of the process or aborted	*/

        working = 0;
        if (stop && !*key)		//since i used calloc to zero the key array, if first char is zero then the array doesn't contain the cracked string
            printf("\nInterrupt signal caught.\n");
        else if (stop)
            printf("\nFilename found: \"%s\".\n", key);
        else
            printf("\nFilename not found.\n");
        free(key);


        /*	Start again?	*/

        printf("\n");
        do
        {
            printf("\nDo you want to crack another hash? [y/n]: ");
            do
            {
                another_hash = (char)getchar();
            } while (another_hash == '\n');
            getchar();	//eliminate trailing \n char, because it will remain in stdin and will be passed to next input catching
        } while ((another_hash != 'y') && (another_hash != 'n'));
        if (another_hash == 'n')
            break;

        stop = 0;
    }

    pre_exit(0);
}
