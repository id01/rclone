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
func testCompressDecompress(t *testing.T, preset string, testString string) {
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
	err = comp.CompressFile(testFileReader, 0, compressedFile)
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
	FileHandle, decompressedSize, err := comp.DecompressFile(compressedFile, size)
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
	t.Logf("Hash of original file: %x\n", testFileHash)
	t.Logf("Hash of recovered file: %x\n", decompressedFileHash)
	if !bytes.Equal(testFileHash, decompressedFileHash) {
		t.Fatal("Hashes do not match!")
	}
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

// Tests LZ4
func TestLZ4CompressSmall(t *testing.T) {
	testCompressDecompress(t, "lz4", TestStringSmall)
}
func TestLZ4CompressLarge(t *testing.T) {
	testCompressDecompress(t, "lz4", getCompressibleString(TestSizeLarge))
}

// Tests Snappy
func TestSnappyCompressSmall(t *testing.T) {
	testCompressDecompress(t, "snappy", TestStringSmall)
}
func TestSnappyCompressLarge(t *testing.T) {
	testCompressDecompress(t, "snappy", getCompressibleString(TestSizeLarge))
}

// Tests GZIP
func TestGzipCompressSmall(t *testing.T) {
	testCompressDecompress(t, "gzip-min", TestStringSmall)
}
func TestGzipCompressLarge(t *testing.T) {
	testCompressDecompress(t, "gzip-min", getCompressibleString(TestSizeLarge))
}

// Tests XZ
func TestXZCompressSmall(t *testing.T) {
	if !checkXZ() {
		t.Skip("XZ binary not found on current system")
	}
	testCompressDecompress(t, "xz-min", TestStringSmall)
}
func TestXZCompressLarge(t *testing.T) {
	if !checkXZ() {
		t.Skip("XZ binary not found on current system")
	}
	testCompressDecompress(t, "xz-min", getCompressibleString(TestSizeLarge))
}
