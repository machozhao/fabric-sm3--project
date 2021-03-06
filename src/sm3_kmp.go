package sm3

/*
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "../kmp/include/keymgrapi.h"
// intentionally write the same LDFLAGS differently
#cgo linux CFLAGS: -I../kmp/include
#cgo linux LDFLAGS: -L/home/ibm/IdeaProjects/fabric-sm3--project/kmp/lib -lKeyMgrApi -ldl
*/
import "C"

import (
	"fmt"
	"hash"
	"unsafe"
	"errors"
)

type SM3_KMP struct {
	sm3Context  unsafe.Pointer // Context required by KMP//
}

type Void interface{}

// http://stackoverflow.com/questions/35673161/convert-go-byte-to-a-c-char

func NewSM3_KMP() hash.Hash {
	//kmpConfigFile := []byte("/home/ibm/IdeaProjects/fabric-sm3--project/kmp/kmp.ini")
	kmpConfigFile := []byte("/etc/kmp.ini")
	//fmt.Println("KMP config file: ", kmpConfigFile)

	sm3 := &SM3_KMP{sm3Context:nil}

	// Init DTCSP
	//sm3.sm3Context = unsafe.Pointer
	//fmt.Println("Before init, sm3 context: ", sm3.sm3Context)
	//var dat unsafe.Pointer
	sm3.sm3Context = C.malloc(C.size_t(unsafe.Sizeof(sm3.sm3Context)))
	//fmt.Println("Before init, sm3 context: ", &sm3.sm3Context)
	rv := C.KMP_Initialize(&sm3.sm3Context, 1, (*C.uchar)(unsafe.Pointer(&kmpConfigFile[0])))
	if rv != 0 {
		fmt.Printf("KMP_Initialize Error, ret: ", rv);
		return nil;
	}
	//fmt.Println("After  init, sm3 context: ", sm3.sm3Context)
	return sm3
}

// Reset clears the internal state by zeroing bytes in the state buffer.
// This can be skipped for a newly-created hash state; the default zero-allocated state is correct.
func (sm3 *SM3_KMP) Reset() {
	// Reset digest
	sm3.sm3Context = nil
}

// BlockSize, required by the hash.Hash interface.
// BlockSize returns the hash's underlying block size.
// The Write method must be able to accept any amount
// of data, but it may operate more efficiently if all writes
// are a multiple of the block size.
func (sm3 *SM3_KMP) BlockSize() int {
	// Here return the number of byte
	return 64
}

// Size, required by the hash.Hash interface.
// Size returns the number of bytes Sum will return.
func (sm3 *SM3_KMP) Size() int {
	return 32
}

func (sm3 *SM3_KMP) Close() {
	rvu := C.KMP_Finalize(&sm3.sm3Context);
	//fmt.Println("After  update, sm3 context: ", sm3.sm3Context)
	if rvu != 0 {
		fmt.Println("got error from finalize: ", rvu)
		return;
	}
}

// Write, required by the hash.Hash interface.
// Write (via the embedded io.Writer interface) adds more data to the running hash.
// It never returns an error.
func (sm3 *SM3_KMP) Write(pInData []byte) (int, error) {
	if pInData != nil {
		return -1, errors.New("Can not support streaming mode, please call Sum(data)");
	}
	return 0, nil
}

// Sum, required by the hash.Hash interface.
// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (sm3 *SM3_KMP) Sum(pInData []byte) []byte {

	if pInData == nil || len(pInData) == 0 {
		return nil
	}
	const hashAlgo = 8

	//fmt.Println("Before update, in data: ", )
	//fmt.Println("Before update, sm3 context: ", sm3.sm3Context)
	//fmt.Println("Before update, in uchar: ", (C.DTCSP_INT32)(len(pInData)))
	var pOutData [64]byte
	var pOutDataLen int
	//rvu := C.KMP_MsgDigest_Ex(sm3.sm3Context, hashAlgo, (*C.uchar)(unsafe.Pointer(&pInDataBuf)), (C.int)(len(pInData)),
	rvu := C.KMP_MsgDigest_Ex(sm3.sm3Context, hashAlgo, (*C.uchar)(unsafe.Pointer(&pInData[0])), (C.int)(len(pInData)),
		(*C.uchar)(unsafe.Pointer(&pOutData[0])), (*C.int)(unsafe.Pointer(&pOutDataLen)));
	//fmt.Println("After  update, sm3 context: ", sm3.sm3Context)
	if rvu != 0 {
		fmt.Println("got error: ", rvu)
		sm3.Close()
		return nil;
	}
	//fmt.Println("Out Len: ", pOutDataLen)
	ret := make([]byte, pOutDataLen)
	for i := 0; i < pOutDataLen; i++ {
		ret[i] = pOutData[i]
		//fmt.Printf("%s\n", ret[i])
	}

	sm3.Close()
	//fmt.Printf("After  Sum, ret: %s", pOutData) 
        return ret
}

//------------------ ALL debug functions

