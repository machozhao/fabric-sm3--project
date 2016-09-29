package sm3

import (
"testing"
"fmt"
)

func TestSM3_DTCSP_Hash(t *testing.T) {
	fmt.Printf("calling TestSM3_DTSCP_Hash\n")
	msg := "a"
	var buffer [3]byte
	copy(buffer[:], msg)
	fmt.Printf("Finished TestSM3_DTSCP_Hash\n")
}