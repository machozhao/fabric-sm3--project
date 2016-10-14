package sm3

import (
"testing"
	"fmt"
)

func Byte2String(b []byte, len int) string {
	ret := ""
	for i := 0; i < len; i++ {
		ret += fmt.Sprintf("%02x", b[i])
	}
	return ret
}

func TestSM3_DTCSP_Hash_1(t *testing.T) {
	trueVal := "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"

	msg := "abc"
	var buffer [3]byte
	copy(buffer[:], msg)

	hw := NewSM3_DTCSP()
	hw.Write(nil)

	uhash := hw.Sum(buffer[:])
	calcVal := Byte2String(uhash, 32)

	if calcVal != trueVal {
		t.Errorf("expected: %s,\nbut got: %s\n", trueVal, calcVal)
	}
}

func TestSM3_DTCSP_Hash_2(t *testing.T) {
	trueVal := "cbdddb8e8421b23498480570d7d75330538a6882f5dfdc3b64115c647f3328c4"

	msg := "1"
	buffer := []byte(msg)

	hw := NewSM3_DTCSP()
	hw.Write(nil)

	uhash := hw.Sum(buffer[:])
	calcVal := Byte2String(uhash, 32)

	if calcVal != trueVal {
		t.Errorf("expected: %s,\nbut got: %s\n", trueVal, calcVal)
	}
}

func TestSM3_DTCSP_Hash_3(t *testing.T) {
	trueVal := "623476ac18f65a2909e43c7fec61b49c7e764a91a18ccb82f1917a29c86c5e88"

	msg := "a"
	buffer := []byte(msg)

	hw := NewSM3_DTCSP()
	hw.Write(nil)

	uhash := hw.Sum(buffer[:])
	calcVal := Byte2String(uhash, 32)

	if calcVal != trueVal {
		t.Errorf("expected: %s,\nbut got: %s\n", trueVal, calcVal)
	}
}



func TestSM3_DTCSP_Hash_4(t *testing.T) {
	trueVal := "010f4f4fed259a7e25fe1b00daebe5ca170b23bdce8555fa77aed53965604ab8"

	msg := "abcdefghijklmn"
	buffer := []byte(msg)

	hw := NewSM3_DTCSP()
	hw.Write(nil)

	uhash := hw.Sum(buffer[:])
	calcVal := Byte2String(uhash, 32)

	if calcVal != trueVal {
		t.Errorf("expected: %s,\nbut got: %s\n", trueVal, calcVal)
	}
}

func TestSM3_DTCSP_Hash_5(t *testing.T) {
	// abcdefghijklmnabcdefghijklmnabcdefghijklmnabcdefghijklmn
	trueVal := "868327542ec16de26186273af07c8eb513b894628ba8574edfab015e07a23bd6"

	msg := "abcdefghijklmnabcdefghijklmn"
	buffer := []byte(msg)

	hw := NewSM3_DTCSP()
	hw.Write(nil)

	uhash := hw.Sum(buffer[:])
	calcVal := Byte2String(uhash, 32)

	if calcVal != trueVal {
		t.Errorf("expected: %s,\nbut got: %s\n", trueVal, calcVal)
	}
}

func TestSM3_DTCSP_stress(t *testing.T) {
	for i := 0; i < 100; i++ {
		TestSM3_DTCSP_Hash_5(t)
	}
}



