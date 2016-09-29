package sm3

/*
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "../dtcsp/include/dtcspapi.h"
// intentionally write the same LDFLAGS differently
#cgo linux CFLAGS: -I../dtcsp/include
#cgo linux LDFLAGS: -L/usr/lib -ldtcsp -lcrypto -ldl
#cgo darwin CFLAGS: -I/Users/gerryyang/github_project/goinaction/src/cgo/inc
#cgo darwin LDFLAGS: -L/usr/lib
*/
import "C"

import (
	"fmt"
	"hash"
	"unsafe"
	"errors"
)

type SM3 struct {
	sm3Context  C.DTCSP_SM3_CONTEXT // Context required by DTCSP//
}

func NewSM3() hash.Hash {
	sm3 := &SM3{}

	// Init DTCSP
	sm3.sm3Context = C.DTCSP_SM3_CONTEXT{}
	//fmt.Println("Before init, sm3 context: ", sm3.sm3Context)

	var ptrnull [64]byte
	rv := C.DTCSP_SM3_Ex_Init(nil, &sm3.sm3Context, 0x06,(*C.DTCSP_UCHAR)(unsafe.Pointer(&ptrnull)),0,0,7, nil)
	//fmt.Println("After  init, sm3 context: ", sm3.sm3Context)
	if rv != 0 {
		fmt.Printf("DTCSP_SM3_Ex_Init Error\n");
		return nil;
	}
	return sm3
}

// Reset clears the internal state by zeroing bytes in the state buffer.
// This can be skipped for a newly-created hash state; the default zero-allocated state is correct.
func (sm3 *SM3) Reset() {
	// Reset digest
	sm3.sm3Context = C.DTCSP_SM3_CONTEXT{}
}

// BlockSize, required by the hash.Hash interface.
// BlockSize returns the hash's underlying block size.
// The Write method must be able to accept any amount
// of data, but it may operate more efficiently if all writes
// are a multiple of the block size.
func (sm3 *SM3) BlockSize() int {
	// Here return the number of byte
	return 64
}

// Size, required by the hash.Hash interface.
// Size returns the number of bytes Sum will return.
func (sm3 *SM3) Size() int {
	return 32
}


// Write, required by the hash.Hash interface.
// Write (via the embedded io.Writer interface) adds more data to the running hash.
// It never returns an error.
func (sm3 *SM3) Write(pInData []byte) (int, error) {
	if pInData != nil {
		const sizeOfBuf = 1
		var pInDataBuf [sizeOfBuf]byte
		var begin int
		var end int
		var total = len(pInData)
		for begin = 0;begin < len(pInData); {
			end += sizeOfBuf
			if end > total {
				end = total;
			}
			// Update hash
			for i:= begin; i < end; i++ {
				pInDataBuf[i - begin] = pInData[i]
			}
			//fmt.Println("Before update, in data: ", )
			//fmt.Println("Before update, sm3 context: ", sm3.sm3Context)
			//fmt.Println("Before update, in uchar: ", (C.DTCSP_INT32)(len(pInData)))
			rvu := C.DTCSP_SM3_Ex_Update(nil, &sm3.sm3Context, (*C.DTCSP_UCHAR)(unsafe.Pointer(&pInDataBuf)), (C.DTCSP_INT32)(end - begin));
			//fmt.Println("After  update, sm3 context: ", sm3.sm3Context)
			if rvu != 0 {
				return int(rvu), errors.New("DTCSP_SM3_Ex_Update Error");
			}
			begin = end;
		}
	}
	return 0, nil
}

// Sum, required by the hash.Hash interface.
// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (sm3 *SM3) Sum(pInData []byte) []byte {

	sm3.Write(pInData)

	var pOutData [32]byte
	//fmt.Println("Before Sum, sm3 context: ", sm3.sm3Context)
	rv := C.DTCSP_SM3_Ex_Final (nil, &sm3.sm3Context, 32, (*C.DTCSP_UCHAR)(unsafe.Pointer(&pOutData)));
	//fmt.Println("After  Sum, sm3 context: ", sm3.sm3Context)
	//fmt.Println("After  Sum, pOut: ", pOutData)
	if rv != 0 {
	   return nil;
	}
	ret := make([]byte, len(pOutData))
	for i := 0; i < 32; i++ {
		ret[i] = pOutData[i]
		//fmt.Println(ret[i])
	}
	//fmt.Println("After  Sum, ret: ", ret)
	return ret
}

//------------------ ALL debug functions

