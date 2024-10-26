//*****************************************************************************************
//**
//** fmadio high speed rsync 
//**
//** Copyright fmad enginering inc 2018 all rights reserved 
//**
//** BSD License 
//**
//*****************************************************************************************

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "fTypes.h"

#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <linux/sched.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <semaphore.h>

#include "fTypes.h"

// standard PCAP header 
#define PCAPHEADER_MAGIC_NANO       0xa1b23c4d
#define PCAPHEADER_MAGIC_USEC       0xa1b2c3d4
#define PCAPHEADER_MAJOR            2
#define PCAPHEADER_MINOR            4
#define PCAPHEADER_LINK_ETHERNET    1

typedef struct
{

	u32             Magic;
	u16             Major;
	u16             Minor;
	u32             TimeZone;
	u32             SigFlag;
	u32             SnapLen;
	u32             Link;

} __attribute__((packed)) PCAPHeader_t;

typedef struct PCAPPacket_t
{
	u32             Sec;                    // time stamp sec since epoch
	u32             NSec;                   // nsec fraction since epoch

	u32             LengthCapture;			// captured length
	u32             LengthWire;				// Length on the wire 

} __attribute__((packed)) PCAPPacket_t;

double TSC2Nano = 0;

//-------------------------------------------------------------------------------------------
typedef struct
{
	u32		Instance;
	u64 	FileCnt;
	u64 	FileSize;

	pthread_t	Thread;

	volatile u64	TotalByte;
	volatile u64	TotalFile;
	volatile bool	IsDone;
} Thread_t;

sem_t s_Sync;

void* SingleCPUTest(void* arg)
{
	Thread_t* I = (Thread_t*)arg;


	printf("%lli\n", I->FileSize);


	// fill buffer with random noise
	u8* Buffer = malloc(I->FileSize);
	assert(Buffer != NULL);

	u32* B32 = (u32*)Buffer;
	for (int i=0; i < I->FileSize/4; i++)
	{
		B32[i] = rand();
	}

	// delete previous temp
	u8 Cmd[1024];
	sprintf(Cmd, "rm -Rf ./tmp_%i/", I->Instance);
	printf("deleting previoud tmp dir\n[%s]\n", Cmd);
	system(Cmd);
		
	// create new temp dir
	sprintf(Cmd, "mkdir ./tmp_%i/", I->Instance);
	printf("creating new tmp\n[%s]\n", Cmd);
	system(Cmd);

	I->TotalFile	= 0;
	I->TotalByte	= 0;

	printf("wait for ready\n");
	sem_post(&s_Sync);
	sem_wait(&s_Sync);

	// generate 1M files each 1MB each
	for (int i=0; i < I->FileCnt; i++)
	{
		u8 Path[1024];
		sprintf(Path, "./tmp_%i/test_file_%i", I->Instance, i);

		FILE* F = fopen(Path, "w");
		assert(F != NULL);

		int wlen = fwrite(Buffer, 1, I->FileSize, F);
		assert(wlen == I->FileSize);

		fclose(F);

		I->TotalByte += I->FileSize;
		I->TotalFile += 1;

		/*
		if (i % 1024 == 0)
		{
			u64 TS  = clock_ns(); 
			float  dT = (TS - TSLast)/1e9;
			s64 dFile = i - FileLast; 
			s64 dByte = TotalByte - ByteLast; 

			float bps = (dByte * 8.0) / dT;
			float fps = dFile / dT;
			
			printf("FileCnt: %8i (%.3f) %.3f GB %.3f Gbps %.3fK FilesPerSec\n", i, 
																				i/(float)I->FileCnt, 
																				I+>TotalByte/1e9, 
																				bps / 1e9, 
																				fps/1000.0);

			TSLast = TS;
			FileLast = i;
			ByteLast = TotalByte;
		}
		*/
	}

	I->IsDone = true;
}

int main(int argc, char* argv[])
{
	CycleCalibration();

	int ThreadCnt 	= 16;				// number of threads
	int FileMax		= 100e3;			// total number of files
	int FileSize	= 1024*1024;		// size of each file

	sem_init(&s_Sync, 0, ThreadCnt);

	// start all the threads
	Thread_t ThreadList[1024];
	for (int t=0; t < ThreadCnt; t++)
	{
		Thread_t* T = &ThreadList[t];
		T->Instance = t;
		T->FileCnt 	= FileMax/ThreadCnt;
		T->FileSize = FileSize; 
		T->IsDone   = false; 
		pthread_create(&T->Thread, NULL, &SingleCPUTest, T);
	}	


	printf("wait for ready\n");
	sem_wait(&s_Sync);

	// monitor it
	u64 TSBegin = clock_ns();
	u64 TSLast  = TSBegin; 

	u64 FileLast	= 0;
	u64 ByteLast	= 0;

	while (true)
	{
		u32 IsDone 	  = true;

		u64 TotalByte = 0;
		u64 TotalFile = 0;

		for (int i=0; i < ThreadCnt; i++)
		{
			TotalByte += ThreadList[i].TotalByte;
			TotalFile += ThreadList[i].TotalFile;

			if (!ThreadList[i].IsDone) IsDone = false;
		}

		u64 TS  = clock_ns(); 
		float  dT = (TS - TSLast)/1e9;
		s64 dFile = TotalFile - FileLast; 
		s64 dByte = TotalByte - ByteLast; 

		float bps = (dByte * 8.0) / dT;
		float fps = dFile / dT;
		
		printf("FileCnt: %8i (%8.3f) %8.3f GB %8.3f Gbps %8.3fK FilesPerSec\n", TotalFile, 
																			TotalFile/(float)(ThreadCnt * FileMax), 
																			TotalByte/1e9, 
																			bps / 1e9, 
																			fps/1000.0);

		TSLast = TS;
		FileLast = TotalFile;
		ByteLast = TotalByte;

		// all threads completed
		if (IsDone) break;

		sleep(1);
	}

	// waiting for all threads to finish
	for (int t=0; t < ThreadCnt; t++)
	{
		pthread_join(ThreadList[t].Thread, NULL);
	}

	// sumamry stats
	{
		u64 TotalByte = 0;
		u64 TotalFile = 0;

		for (int i=0; i < ThreadCnt; i++)
		{
			TotalByte += ThreadList[i].TotalByte;
			TotalFile += ThreadList[i].TotalFile;
		}

		u64 TS  = clock_ns(); 
		float  dT = (TS - TSBegin)/1e9;
		s64 dFile = TotalFile;
		s64 dByte = TotalByte;

		float bps = (dByte * 8.0) / dT;
		float fps = dFile / dT;
		
		printf("Summary: FileCnt: %8i (%8.3fM) %8.3f GB %8.3f Gbps %8.3fK FilesPerSec\n", 	TotalFile, 
																							TotalFile/1e6,
																							TotalByte/1e9, 
																							bps / 1e9, 
																							fps/1000.0);
	}
}
