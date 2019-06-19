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
*/

// For testing purposes: Hash=(0x)280F5FD7008898E6 | prefix=build/gumpartlegacymul/ | suffix=.tga | min_len=1 | max_len=8 | charset=0123456789 | result = build/gumpartlegacymul/00001283.tga

//TODO
//linux and mac test for priority setting

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <signal.h>
#include <time.h>

#if defined (_WIN32)
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
#elif defined (__linux__) || defined (__APPLE__) || defined (UNIX)
    #include <unistd.h>
    #include <sys/resource.h>
#endif
#ifdef _WIN32
    #include <malloc.h>
    #ifdef _MSC_VER
        #define alloca _alloca
    #endif
#else
    #include <alloca.h>
#endif

//Size for the char array containing input (before transferring it into the different variables)
#define MAX_ARG_LEN 60

typedef unsigned long long ullong;


/*	Global Vars	*/

//values will be assigned in the main function; they are accessed by multiple functions
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
char* key;	                //for the matching (cracked) string (prefix+filename+suffix)

// globals for cracking
uint32_t hash_magic = 0;                //preprocessed var for hash calculation
unsigned int generated_len = 0;         //length of generated string
unsigned int generated_len_minus = 0;   //generated_len - 1
unsigned int concatenated_len = 0;      //length of concatenated string

const char* stack_charset = NULL;       //copy of charset on the stack, instead of reading that from the heap
char* stack_concatenated = NULL;		//concatenated string (prefix+generatedString+suffix)
char* stack_concatenated_offset = NULL; //pointer to the place in the concatenated string (allocated on the stack) where to start to put the generatedString

// to manage the process
char working = 0;
char stop = 0;


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

//This is a slightly optimized adaptation of the C# algorithm by Malganis; it is included in Mythic Package Editor sources
static inline ullong hashcalc()
{
    uint32_t eax, ecx, edx, ebx, esi, edi;

    eax = ecx = edx = 0;
    ebx = edi = esi = hash_magic;
    //ebx = edi = esi = (uint32_t)concatenated_len + 0xDEADBEEF;

    unsigned int i, diff;

#define str stack_concatenated //for the sake of shortness
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

#undef str

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


/* Brute force function */

static void crack_recurse(const unsigned int position)
{
    for (unsigned int i = 0; i < charset_len; ++i)
    {
        stack_concatenated_offset[position] = stack_charset[i];
        if (position < generated_len_minus)
        {
            crack_recurse(position + 1);
        }
        else
        {
            if (hashcalc() == hash)
            {
                stop = 1;
                strcpy(key, stack_concatenated);
                return;
            }
        }
    }
}

/* Core */
static void start_crack()
{
    working = 1;

    /* Initializing initialize-once variables */

    printf("\nTo abort the computation, press CTRL + C.");
    printf("\nStarting...\n");

    //note: as said, strlen doesn't count the terminator '\0', which in this case is fine
    key_maxlen = prefix_len + filename_maxlen + suffix_len + 1;	//+1 for the "\0" terminator
    key = calloc(key_maxlen, sizeof(char));

    // Having *very* frequently accessed vars allocated in the stack instead of the heap results in faster access
    //  (even if, i have to say, with Visual Studio 2019 x64 and every optimization, i can't notice the difference in speed, which is great in the parallel version instead)
    // Memory allocated with alloca is freed at the exit of the function (not of the scope): don't allocate more than once.
    stack_charset = alloca((charset_len + 1) * sizeof(char));
    memcpy((char*)stack_charset, charset, charset_len + 1);

    stack_concatenated = alloca((key_maxlen + 1) * sizeof(char));
    stack_concatenated_offset = stack_concatenated + prefix_len;


    /* Loop that generates and checks strings of increasing length */

    time_t t; //for time tracking
    for (generated_len = filename_minlen; generated_len <= filename_maxlen && !stop; ++generated_len)
    {
        /* initialize variables for: generated string, concatenated string, concatenated string length */
        concatenated_len = prefix_len + generated_len + suffix_len;

        memcpy(stack_concatenated, prefix, prefix_len);
        memcpy(stack_concatenated + prefix_len + generated_len, suffix, suffix_len);
        *(stack_concatenated + concatenated_len) = '\0';

        hash_magic = (uint32_t)concatenated_len + 0xDEADBEEF;
        generated_len_minus = generated_len - 1;

        time(&t);
        printf("Checking passwords width [ %d ]...   Started: %s", generated_len, asctime(localtime(&t)));

        crack_recurse(filename_minlen - 1);
    }

    time(&t);
    printf("Ended: %s", asctime(localtime(&t)));

    working = 0;
}


int main()
{
    printf("UOHC: Ultima Online UOP Hash Cracker.");
    printf("\nv2.0.1 CPU SERIAL algorithm (single-threaded).");

    /*	Enable handling CTRL + C */

    if (signal(SIGINT, sig_handler) == SIG_ERR)
        printf("\n\nWarning: Can't catch SIGINT. If you want to stop the program you have to close it manually.\n");


    /* Setting high priority for the process */

    printf("\n\nSetting high process priority... ");
    char priority = -1;
#if defined _WIN32
    HANDLE hCurrentProcess = GetCurrentProcess();
    priority = (char)SetPriorityClass(hCurrentProcess, ABOVE_NORMAL_PRIORITY_CLASS);
#elif defined (__linux__) || defined (__APPLE__) || defined (UNIX)
    if (setpriority(PRIO_PROCESS, 0, -20) == -1)
        priority = 0;
    else
        priority = 1;
    //must be superuser?
//needed option for mac
#endif
    switch (priority)
    {
    case -1: printf("Operation unsupported for current OS.\n"); break;
    case 0:  printf("Error, did not change priority. Must run as administrator?\n"); break;
    case 1:  printf("Done.\n"); break;
    default: printf("Default error?\n"); break;
    }

    char another_hash = 0;  //stores the answer when asked for cracking another hash
    char* buf = calloc(MAX_ARG_LEN, sizeof(char));			//initialize buffer for storing inserted parameters
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
        } while (another_hash != 'y' && another_hash != 'n');
        if (another_hash == 'n')
            break;

        stop = 0;
    }
    
    pre_exit(0);
}



