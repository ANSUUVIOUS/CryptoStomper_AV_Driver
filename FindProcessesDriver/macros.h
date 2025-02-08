#pragma once

#include <Ntifs.h>
#include <ntddk.h>
#include <wdm.h>




#pragma comment(lib, "NtosKrnl.lib")


//#define ULONG unsigned long
#define UINT unsigned int
#define DRIVER_TAG 0xDEADBEEF
#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)

#define FREE(p, n) \
do \
{ \
	if(p){\
		memset(p, 0, (SIZE_T)n);   \
		ExFreePoolWithTag(p, (ULONG)DRIVER_TAG); \
	}\
} \
while(0)

#define WLEN(p) \
	wcslen(p)*sizeof(WCHAR) + sizeof(WCHAR)\


#define SLEN(p) \
do \
{ \
	if(p){\
		return strlen(p) + sizeof(PCHAR)\
	}\
} \
while(0)


#define WCSFREE(p) \
do \
{ \
	if(!p){\
		memset(p, 0, wcslen(p)*sizeof(WCHAR) + sizeof(WCHAR));   \
		ExFreePoolWithTag(p, (ULONG)DRIVER_TAG); \
		p = NULL; \
	}\
} \
while(0)

#define STRFREE(p)\
do \
{ \
if (p != NULL) {\
	\
		memset(p, 0, strlen(p));   \
		ExFreePool(p); \
		p = NULL; \
}\
} \
while (0)

#define POOL_ALLOC(p, n) \
  (p) = ExAllocatePoolWithTag(PagedPool, n, (ULONG)DRIVER_TAG) \



#define CHECK_HAND(handle, stmt) \
	do { \
		if ((NULL == handle) || (INVALID_HANDLE_VALUE == handle)) {KdPrint(("Invalid Handle\n")); stmt;} \
	} while(0)


#define CHECK_VALID(p, stmt) \
	do { \
		if ((!p)) { stmt;} \
	} while(0)


#define IS_SUCCESS(p) \
	do { \
		if ((!p)) {goto cleanup;} \
	} while(0)


