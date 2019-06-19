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

//TODO
//support no prefix or suffix

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
/*
#ifdef _MSC_VER
    #include <malloc.h>
    #define alloca _alloca
#else
    #include <alloca.h>
#endif
*/

//Size for the char array containing input (before transferring it into different variables)
#define MAX_ARG_LEN 60

//Enable parallelization using OpenMP:
//	you need to add the option -fopenmp to gcc, /openmp to cl (visual C++ compiler) or -openmp-stubs to ICC (intel C compiler)
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


/* Hash function */

//This is a slightly optimized adaptation of the C# algorithm by Malganis, which is included in Mythic Package Editor sources
static inline ullong hashcalc(const char* str, const unsigned int concat_len, const uint32_t concat_len_reg)
{
    uint32_t eax, ecx, edx, ebx, esi, edi;

    eax = ecx = edx = 0;
    ebx = edi = esi = concat_len_reg;
    //ebx = edi = esi = (uint32_t)concat_len + 0xDEADBEEF;

    unsigned int i, diff;

    for (i = 0; i + 12 < concat_len; i += 12)
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

    diff = (concat_len - i);
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


/* Custom power function */

static inline ullong my_power(const unsigned int base, const unsigned int exp) //meant to be used only for positive numbers!
{
    if (exp == 0)
        return 1;
    ullong res = base;
    for (unsigned int x = 1; x < exp; ++x)
        res *= base;
    return res;
}


/*	Handler for CTRL + C */

void sig_handler(int signo)
{
    if (working)
        stop = 1;
}


/* Main function, here happens most of the stuff */

int main()
{
    printf("UOHC: Ultima Online UOP Hash Cracker.");
    printf("\nv2.0 CPU PARALLEL.");
#if (PARALLELIZATION)
    printf("\nCompiled with OpenMP support (multi-threaded): on a decent multi-core cpu is faster than SERIAL algorithm.\n");
#else
    printf("\nCompiled WITHOUT OpenMP support (single-threaded, always slower than serial).\n");
#endif


    /*	Enable handling CTRL + C */

    if (signal(SIGINT, sig_handler) == SIG_ERR)
        printf("\nWarning: Can't catch SIGINT. If you want to stop the program you have to close it manually.\n");

    time_t t;			    //for time tracking
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
        }
        else
        {
            printf("Charset [%s]: ", charset);
            fgets(buf, MAX_ARG_LEN, stdin);
            if (*buf != '\n')
            {
                charset = realloc(charset, strlen(buf) * sizeof(char));
                strcpy(charset, buf);
            }
        }
        charset_len = (unsigned)(strlen(charset) - 1);
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
        }
        else
        {
            printf("Prefix [%s]: ", prefix);
            fgets(buf, MAX_ARG_LEN, stdin);
            if (*buf != '\n')
            {
                prefix = realloc(prefix, strlen(buf) * sizeof(char));
                strcpy(prefix, buf);
            }
        }
        prefix_len = (unsigned)(strlen(prefix) - 1);
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
        }
        else
        {
            printf("Suffix [%s]: ", suffix);
            fgets(buf, MAX_ARG_LEN, stdin);
            if (*buf != '\n')
            {
                suffix = realloc(suffix, strlen(buf) * sizeof(char));
                strcpy(suffix, buf);
            }
        }
        suffix_len = (unsigned)(strlen(suffix) - 1);
        suffix[suffix_len] = '\0';
        memset(buf, '\0', MAX_ARG_LEN * sizeof(char));


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

        for (unsigned int generated_len = 1; generated_len <= filename_maxlen; ++generated_len)
        {
            // TODO: check if new combinations_max becomes < than old combinations_max (catch overflow)
            combinations_max += my_power(charset_len, generated_len);
            combinations_len[generated_len] = combinations_max;
        }
        combinations_len[0] = 0;

        printf("\nStarting...\n");
        working = 1;


        /* Start generating strings */

        unsigned int curlen;      //length of the strings generated for this cycle
        unsigned int curtotlen;   //length of the strings generated for this cycle, concatenated to prefix and suffix
        ullong seed_len_first;    //first seed generating a string of length "curlen"
        ullong seed_len_slast;    //second last (penultimate) seed generating a string of length "curlen"
        //ullong seed = 0;        //seed from which the string is generated; seed determine both length and characters
        for (curlen = filename_minlen; (curlen <= filename_maxlen) && !stop; ++curlen)
        {
            curtotlen = prefix_len + curlen + suffix_len;
            seed_len_first = combinations_len[curlen - 1];
            seed_len_slast = combinations_len[curlen];
            time(&t);
            printf("Checking passwords width [ %d ]...   Started: %s", curlen, asctime(localtime(&t)));

            char* concat = NULL;
            #pragma omp parallel private(concat) if (PARALLELIZATION)
            {
                const unsigned int local_curtotlen = curtotlen;

                /* initialize the arrays that will contain the generated and the concatenated string */
                // thanks to the private keyword of the pragma omp parallel, each thread has for itself a local copy of
                //	concat, so that calling calloc inside this block creates a concat for each thread.
                concat = malloc((local_curtotlen + 1) * sizeof(char));
                *(concat + local_curtotlen) = '\0';

                memcpy(concat, prefix, prefix_len);
                memcpy(concat + prefix_len + curlen, suffix, suffix_len);
                char* generate_offset = concat + prefix_len;     // where to store the generated string

                // prepare this value for hash function; it's convenient to do this operation once for
                //	each group of strings of fixed length, instead of at each function call
                const uint32_t hash_curtotlen = (uint32_t)local_curtotlen + 0xDEADBEEF;

                // store in contiguous memory once this stuff (faster access, less assembly instructions and memory reads)
                const ullong local_hash = hash;
                const unsigned int local_charset_len = charset_len;
                const char* local_charset = charset;
                // not sure if local_seed_* are useful, i didn't check the generated assembly for them, but i did for the vars above
                const ullong local_seed_len_first = seed_len_first;
                const ullong local_seed_len_slast = seed_len_slast;

                if (local_seed_len_slast <= UINT_MAX)
                {
                    // no need to use 64 bits registers and operations if we know that 32 bits one will suffice (for the current max seed)
                    //  (performance improvement is real)
                    const unsigned int local_uint_seed_len_slast = (unsigned int)local_seed_len_slast;
                    unsigned int seed;
                    #pragma omp for schedule(static) private(seed)
                    for (seed = (unsigned int)local_seed_len_first; seed < local_uint_seed_len_slast; ++seed)
                    {
                        if (!stop)	// need to check if we have finished by this way because of OpenMP
                        {
                            /* generate the string from the seed */
                            unsigned int seed_p = seed;
                            for (unsigned int pos = 0; pos < curlen; ++pos)
                            {
                                *(generate_offset + pos) = local_charset[seed_p % local_charset_len];
                                seed_p /= local_charset_len;
                            }

                            /* check if the hashed string matches the hash we are cracking */
                            if (hashcalc(concat, local_curtotlen, hash_curtotlen) == local_hash)
                            {
                                stop = 1;
                                strcpy(key, concat);
                            }
                        }
                    }
                }
                else
                {
                    ullong seed;
                    #pragma omp for schedule(static) private(seed)
                    for (seed = local_seed_len_first; seed < local_seed_len_slast; ++seed)
                    {
                        if (!stop)	// need to check if we have finished by this way because of OpenMP
                        {
                            /* generate the string from the seed */
                            ullong seed_p = seed;
                            for (unsigned int pos = 0; pos < curlen; ++pos)
                            {
                                *(generate_offset + pos) = local_charset[seed_p % local_charset_len];
                                seed_p /= local_charset_len;
                            }

                            /* check if the hashed string matches the hash we are cracking */
                            if (hashcalc(concat, curtotlen, hash_curtotlen) == local_hash)
                            {
                                stop = 1;
                                strcpy(key, concat);
                            }
                        }
                    }
                }


                free(concat);
            }
        }

        time(&t);
        printf("Ended: %s", asctime(localtime(&t)));


        /*	End of the process or aborted	*/

        working = 0;
        if (stop && !*key)		//since i used calloc to zero the key array, if first char is zero then the array doesn't contain the cracked string
            printf("\nInterrupt signal caught.\n");
        else if (stop)
            printf("\nFilename found: \"%s\".\n", key);
        else
            printf("\nFilename not found.\n");

        free(combinations_len);
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

    printf("\nExiting.");
}
