# EAC Logchecker

This is a transparent implementation of the Exact Audio Copy log checksum algorithm, written in Go.

This is a fork of https://github.com/puddly/eac_logsigner, with modifications to have it
better match the output of the actual EAC Logchecker to be used in downstream applications. All
credit goes to puddly for reverse-engineering the closed source EAC to develop the base.

## Installation

Download from [releases](https://github.com/Nirzak/eac-logchecker/releases).

## Usage

Verify logs:

    Usage: eac-logchecker [--json] [--version] <file>

Sign or fix existing logs:

    Usage: eac-logchecker sign [--force] <input_log> <output_log>

## Example

### Verify

    $ ./eac-logchecker logs/01.log
    Log Integrity Checker   (C) 2010 by Andre Wiethoff

    1. Log entry is fine!

    $ ./eac-logchecker logs/05.log
    Log Integrity Checker   (C) 2010 by Andre Wiethoff

    1. Log entry is fine!
    2. Log entry is fine!

    $ ./eac-logchecker --json logs/05.log
    [{"message": "Log entry is fine!", "status": "OK"}, {"message": "Log entry is fine!", "status": "OK"}]

### Sign

    $ ./eac-logchecker sign logs/01.log signed.log
    Signed: <CHECKSUM_HEX>


## Use it as a go package

```go
import "github.com/Nirzak/eac-logchecker/eaclogchecker"

// Verify a log
results := eaclogchecker.CheckChecksum("path/to/file.log")
for _, r := range results {
    fmt.Println(r.Status, r.Message)
}

// Sign a log
err := eaclogchecker.SignLog("input.log", "output.log", false)
```

## Algorithm

 1. Strip the log file of newlines and BOMs.
 2. Cut off the existing signature block and (re-)encode the log text back into little-endian UTF-16
 3. Encrypt the log file with Rijndael-256:
    * in CBC mode
    * with a 256-bit block size (most AES implementations hard-code a 128-bit block size)
    * all-zeroes IV
    * zero-padding
    * the hex key `9378716cf13e4265ae55338e940b376184da389e50647726b35f6f341ee3efd9`
 4. XOR together all of the resulting 256-bit ciphertext blocks. You can do it byte-by-byte, it doesn't matter in the end.
 5. Output the little-endian representation of the above number, in uppercase hex.
