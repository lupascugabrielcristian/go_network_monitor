package main

import (
	_"fmt"
	"math/rand"
	"time"
	"os"
	"strconv"
)

// How many ip's to generate
var amount int = 30

// Range for 3rd byte
var thirdByte int
var thirdByteMin = 28
var thirdByteMax = 30

// Range for last byte
var lastByte int
var lastByteMin = 0
var lastByteMax = 254

var firstPart = "103.30."

func main() {
	// Make ips.list file to hold generated ips
	f, err := os.Create("ips.list")
	if err != nil {
		panic("No file")
	}
	// remember to close the file
    defer f.Close()

	// To obtain different results each run
	rand.Seed(time.Now().UnixNano())

	// Generate all ip's
	counter := 0
	generatedIps := make([]string, amount + 1)

	for counter < amount {
		counter++

		// make 3rd byte
		thirdByte = rand.Intn(thirdByteMax-thirdByteMin) + thirdByteMin

		// make random last ip byte
		lastByte := rand.Intn(lastByteMax-lastByteMin) + lastByteMin

		generated := firstPart + strconv.Itoa(thirdByte) + "." + strconv.Itoa(lastByte) + "\n"
		generatedIps[counter] = generated
	}

	// Write all ip's to a file
	for _, ip := range generatedIps {
		f.WriteString(ip)
	}
}
