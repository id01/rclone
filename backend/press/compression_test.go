package press

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"strings"
	"testing"
)

const TestStringSmall = "The quick brown fox jumps over the lazy dog."
const TestSizeLarge = 2097152 // 2 megabytes

// Tests compression and decompression for a preset
func testCompressDecompress(t *testing.T, preset string, testString string, externalData bool) {
	// Create compression instance
	comp, err := NewCompressionPreset(preset)
	if err != nil {
		t.Fatal(err)
	}

	// Open files and hashers
	testFile := strings.NewReader(testString)
	testFileHasher := md5.New()
	if err != nil {
		t.Fatal(err)
	}
	compressedFile, err := ioutil.TempFile(os.TempDir(), "rclone_compression_test")
	if err != nil {
		t.Fatal(err)
	}
	outHasher := md5.New()

	// Compress file and hash it (size doesn't matter here)
	testFileReader, testFileWriter := io.Pipe()
	go func() {
		_, err := io.Copy(io.MultiWriter(testFileHasher, testFileWriter), testFile)
		if err != nil {
			t.Fatal("Failed to write compressed file")
		}
		err = testFileWriter.Close()
		if err != nil {
			t.Log("Failed to close compressed file")
		}
	}()
	var blockData []uint32
	if externalData {
		blockData, err = comp.CompressFileReturningBlockData(testFileReader, compressedFile)
	} else {
		err = comp.CompressFileAppendingBlockData(testFileReader, compressedFile)
	}
	if err != nil {
		t.Fatalf("Compression failed with error: %v", err)
	}
	testFileHash := testFileHasher.Sum(nil)

	// Get the size, seek to the beginning of the compressed file
	size, err := compressedFile.Seek(0, io.SeekEnd)
	if err != nil {
		t.Fatal(err)
	}
	_, err = compressedFile.Seek(0, io.SeekStart)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Compressed size: %d\n", size)

	// Decompress file into a hasher
	var FileHandle io.ReadSeeker
	var decompressedSize int64
	if externalData {
		FileHandle, decompressedSize, err = comp.DecompressFileExtData(compressedFile, size, blockData)
	} else {
		FileHandle, decompressedSize, err = comp.DecompressFile(compressedFile, size)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Decompressed size: %d\n", decompressedSize)
	bufr := bufio.NewReaderSize(FileHandle, 12345678)
	_, err = io.Copy(outHasher, bufr)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	decompressedFileHash := outHasher.Sum(nil)

	// Clean up
	err = compressedFile.Close()
	if err != nil {
		t.Log("Warning: cannot close compressed test file")
	}
	err = os.Remove(compressedFile.Name())
	if err != nil {
		t.Log("Warning: cannot remove compressed test file")
	}

	// Compare hashes
	if !bytes.Equal(testFileHash, decompressedFileHash) {
		t.Logf("Hash of original file: %x\n", testFileHash)
		t.Logf("Hash of recovered file: %x\n", decompressedFileHash)
		t.Fatal("Hashes do not match!")
	}
}

// Tests both small and large strings for a preset
func testSmallLarge(t *testing.T, preset string, externalData bool) {
	testStringLarge := getCompressibleString(TestSizeLarge)
	t.Run("TestSmall", func(t *testing.T) {
		testCompressDecompress(t, preset, TestStringSmall, externalData)
	})
	t.Run("TestLarge", func(t *testing.T) {
		testCompressDecompress(t, preset, testStringLarge, externalData)
	})
}

// Tests both appended and external data modes for a preset
func testInternalExternal(t *testing.T, preset string) {
	t.Run("TestExternal", func(t *testing.T) {
		testSmallLarge(t, preset, true)
	})
	t.Run("TestAppended", func(t *testing.T) {
		testSmallLarge(t, preset, false)
	})
}

// Gets a compressible string
func getCompressibleString(size int) string {
	// Get pseudorandom bytes
	prbytes := make([]byte, size*3/4+16)
	prsource := rand.New(rand.NewSource(0))
	prsource.Read(prbytes)
	// Encode in base64
	encoding := base64.NewEncoding("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/")
	return encoding.EncodeToString(prbytes)[:size]
}

func TestCompression(t *testing.T) {
	testCases := []string{"lz4", "snappy", "gzip-min"}
	if checkXZ() {
		testCases = append(testCases, "xz-min")
	} else {
		t.Log("XZ binary not found on current system. Not testing xz.")
	}
	for _, tc := range testCases {
		t.Run(tc, func(t *testing.T) {
			testInternalExternal(t, tc)
		})
	}
}
