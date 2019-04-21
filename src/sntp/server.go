package sntp

import (
	"errors"
	"time"
	"encoding/binary"
	"strconv"
)

// Serve handle incoming SNTP request and generate a response
func Serve(req []byte) ([]byte, error) {
	if checkClientRequest(req) {
		return generate(req), nil
	}
	return []byte{}, errors.New("invalid format")
}


const (
	LiNoWarning           = 0
	LiAlarmCondition      = 3
	VnFirst               = 1
	VnLast                = 4
	ModeClient            = 3
)

var (
	bitMask2 byte
	bitMask3 byte
)

func init() {
	bitMask2tmp, _ := strconv.ParseUint("11", 2, 8)
	bitMask2 = byte(bitMask2tmp)
	bitMask3tmp, _ := strconv.ParseUint("111", 2, 8)
	bitMask3 = byte(bitMask3tmp)
}

// checkClientRequest checks if client send valid request
//
// Leap Indicator - must be 0 (NoWarning) or 3 (AlarmCondition (clock not synchronized))
// Version Number - must be between 1 (oldest) and 4 (newest)
// Mode           - must be 3 (Client)
func checkClientRequest(req []byte) bool {
	// bits 0,1
	var leapIndicator = req[0] >> 6 & bitMask2
	// bits 2,3,4
	var versionNumber = req[0] >> 3 & bitMask3
	// bits 5,6,7
	var mode = req[0] & bitMask3

	if leapIndicator != LiNoWarning && leapIndicator != LiAlarmCondition {
		return false
	}
	if versionNumber < VnFirst || versionNumber > VnLast {
		return false
	}
	if mode != ModeClient {
		return false
	}
	return true
}

const (
	SecondsFrom1900To1970 = 2208988800
)

func generate(req []byte) []byte {
	var res = make([]byte, 48)

	var now = time.Now()
	// NTP have seconds from January 1st 1900 and the Unix time starts at January 1st 1970
	var second = now.Unix() + SecondsFrom1900To1970
	var fraction = int64(now.Nanosecond()) << 32 / 1000000000

	var secondBytes = make([]byte, 4)
	binary.BigEndian.PutUint32(secondBytes, uint32(second))

	var fractionBytes = make([]byte, 4)
	binary.BigEndian.PutUint32(fractionBytes, uint32(fraction))

	// Leap Indicator, Version Number and Mode
	// bits 0,1 - 0 (No Warning)
	var leapIndicator byte = LiNoWarning
	// bits 2,3,4 - copied from request
	var versionNumber byte = req[0] >> 3 & bitMask3
	// bits 5,6,7 - mode 4 (Server)
	var mode byte = 4
	res[0] = leapIndicator << 6 + versionNumber << 3 + mode

	// Stratum - 1 (Primary Reference)
	var stratum byte = 1
	res[1] = stratum

	// Poll Interval - 2^n seconds
	var pollInterval byte = 4
	res[2] = pollInterval

	// Precision - precision of system clock as exponent of 2
	var precision int8 = -127
	res[3] = byte(precision)

	// Root delay
	// This is a 32-bit signed fixed-point number indicating the total roundtrip delay to the primary reference source,
	// in seconds with the fraction point between bits 15 and 16.
	// NOT AVAILABLE
	copy(res[4:8], []byte{0,0,0,0})

	// Root Dispersion
	// This is a 32-bit unsigned fixed-point number indicating the maximum error due to the clock frequency tolerance,
	// in seconds with the fraction point between bits 15 and 16.
	// NOT AVAILABLE
	copy(res[8:12], []byte{0,0,0,0})

	// Reference Identifier
	// This is a 32-bit bitstring identifying the particular reference source.
	// LOCL - uncalibrated local clock
	copy(res[12:16], []byte("LOCL"))

	// Reference Timestamp
	// This field is the time the system clock was last set or corrected, in 64-bit timestamp format.
	copy(res[16:20], secondBytes)
	copy(res[20:24], fractionBytes)

	// Originate Timestamp
	// This is the time at which the request departedt he client for the server, in 64-bit timestamp format.
	copy(res[24:32], req[40:48])

	// Receive Timestamp
	// This is the time at which the request arrived at the server or the reply arrived at the client, in 64-bit timestamp format.
	copy(res[32:36], secondBytes)
	copy(res[36:40], fractionBytes)

	// Transmit Timestamp
	// This is the time at which the request departed the client or the reply departed the server, in 64-bit timestamp format.
	copy(res[40:48], res[32:40])

	return res
}
