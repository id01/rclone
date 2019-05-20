// Package press provides wrappers for Fs and Object which implement compression.
package press

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"time"
	"encoding/hex"

	"github.com/ncw/rclone/fs"
	"github.com/ncw/rclone/fs/accounting"
	"github.com/ncw/rclone/fs/chunkedreader"
	"github.com/ncw/rclone/fs/config/configmap"
	"github.com/ncw/rclone/fs/config/configstruct"
	"github.com/ncw/rclone/fs/fspath"
	"github.com/ncw/rclone/fs/hash"
	"github.com/pkg/errors"
)

/**
NOTES:
Filenames are now <original file name>.<extension>
Size() function is really inefficient because it requires opening and seeking through the file
Files are now always compressed - the heuristic test function is defunct (for now)
**/

// Globals
// Register with Fs
func init() {
	// Build compression mode options. Show XZ options only if they're supported on the current system.
	compressionModeOptions := []fs.OptionExample{{ // Default compression mode options
		Value: "lz4",
		Help:  "Fast, real-time compression with reasonable compression ratios.",
	}, {
		Value: "snappy",
		Help:  "Google's compression algorithm. Slightly faster and larger than LZ4.",
	}, {
		Value: "gzip-min",
		Help:  "Standard gzip compression with fastest parameters.",
	}, {
		Value: "gzip-default",
		Help:  "Standard gzip compression with default parameters.",
	},
	}
	if checkXZ() { // If XZ is on the system, append compression mode options that are only available with the XZ binary installed
		compressionModeOptions = append(compressionModeOptions, []fs.OptionExample{{
			Value: "xz-min",
			Help:  "Slow but powerful compression with reasonable speed.",
		}, {
			Value: "xz-default",
			Help:  "Slowest but best compression.",
		},
		}...)
	}

	// Register our remote
	fs.Register(&fs.RegInfo{
		Name:        "press",
		Description: "Compress a remote",
		NewFs:       NewFs,
		Options: []fs.Option{{
			Name:     "remote",
			Help:     "Remote to compress.",
			Required: true,
		}, {
			Name:     "compression_mode",
			Help:     "Compression mode. Installing XZ will unlock XZ modes.",
			Default:  "gzip-min",
			Examples: compressionModeOptions,
		}},
	})
}

// Constants
const bufferSize = 8388608 // Size of buffer when compressing or decompressing the entire file.
// Larger size means more multithreading with larger block sizes and thread counts.
// Currently at 8MB.
const initialChunkSize = 262144 // Initial and max sizes of chunks when reading parts of the file. Currently
const maxChunkSize = 8388608    // at 256KB and 8 MB.

const metaFileExt = ".meta"
var (
	ErrDecodingMetadata = errors.New("error decoding metadata")
)

// newCompressionForConfig constructs a Compression object for the given config name
func newCompressionForConfig(opt *Options) (*Compression, error) {
	c, err := NewCompressionPreset(opt.CompressionMode)
	return c, err
}

// NewFs contstructs an Fs from the path, container:path
func NewFs(name, rpath string, m configmap.Mapper) (fs.Fs, error) {
	// Parse config into Options struct
	opt := new(Options)
	err := configstruct.Set(m, opt)
	if err != nil {
		return nil, err
	}
	c, err := newCompressionForConfig(opt)
	if err != nil {
		return nil, err
	}
	remote := opt.Remote
	if strings.HasPrefix(remote, name+":") {
		return nil, errors.New("can't point press remote at itself - check the value of the remote setting")
	}
	wInfo, wName, wPath, wConfig, err := fs.ConfigFs(remote)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse remote %q to wrap", remote)
	}
	// Strip trailing slashes if they exist in rpath
	rpath = strings.TrimRight(rpath, "\\/")

	// First, check for a file
	// If a metadata file was found, return an fs with it. Otherwise, check for a directory
	remotePath := fspath.JoinRootPath(wPath, generateMetadataName(rpath))
	wrappedFs, err := wInfo.NewFs(wName, remotePath, wConfig)
	if err != fs.ErrorIsFile {
		remotePath = fspath.JoinRootPath(wPath, rpath)
		wrappedFs, err = wInfo.NewFs(wName, remotePath, wConfig)
	}
	if err != nil && err != fs.ErrorIsFile {
		return nil, errors.Wrapf(err, "failed to make remote %s:%q to wrap", wName, remotePath)
	}

	// Create the wrapping fs
	f := &Fs{
		Fs:   wrappedFs,
		name: name,
		root: rpath,
		opt:  *opt,
		c:    c,
	}
	// the features here are ones we could support, and they are
	// ANDed with the ones from wrappedFs
	f.features = (&fs.Features{
		CaseInsensitive:         true,
		DuplicateFiles:          true,
		ReadMimeType:            false,
		WriteMimeType:           false,
		BucketBased:             true,
		CanHaveEmptyDirectories: true,
		SetTier:                 true,
		GetTier:                 true,
	}).Fill(f).Mask(wrappedFs).WrapsFs(f, wrappedFs)

	return f, err
}

// Processes a file name for a compressed file. Returns the original file name, the extension, and the size of the original file.
func processFileName(compressedFileName string) (origFileName string, extension string, err error) {
	// Separate the filename from the extension
	extensionPos := strings.LastIndex(compressedFileName, ".")
	if extensionPos == -1 {
		return "", "", errors.New("File name has no extension")
	}
	name := compressedFileName[:extensionPos]
	extension = compressedFileName[extensionPos:]
	// Return everything
	return name, extension, nil
}

// Generates the file name for a metadata file
func generateMetadataName(remote string) (newRemote string) {
	return remote + metaFileExt
}

// Checks whether a file is a metadata file
func isMetadataFile(filename string) bool {
	return strings.HasSuffix(filename, metaFileExt)
}

// Generates the file name for a data file
func (c *Compression) generateDataName(remote string) (newRemote string) {
	return remote + c.GetFileExtension()
}

// Options defines the configuration for this backend
type Options struct {
	Remote          string `config:"remote"`
	CompressionMode string `config:"compression_mode"`
}

/*** FILESYSTEM FUNCTIONS ***/

// Fs represents a wrapped fs.Fs
type Fs struct {
	fs.Fs
	wrapper  fs.Fs
	name     string
	root     string
	opt      Options
	features *fs.Features // optional features
	c        *Compression
}

// Name of the remote (as passed into NewFs)
func (f *Fs) Name() string {
	return f.name
}

// Root of the remote (as passed into NewFs)
func (f *Fs) Root() string {
	return f.root
}

// Features returns the optional features of this Fs
func (f *Fs) Features() *fs.Features {
	return f.features
}

// String returns a description of the FS
func (f *Fs) String() string {
	return fmt.Sprintf("Compressed drive '%s:%s'", f.name, f.root)
}

// Remove the last extension of the file that is used for determining whether a file is compressed.
func (f *Fs) add(entries *fs.DirEntries, obj fs.Object) {
	remote := obj.Remote()
	_, _, err := processFileName(remote)
	if err != nil {
		fs.Debugf(remote, "Skipping unrecognized file name: %v", err)
		return
	}
	*entries = append(*entries, f.NewObject(obj))
}

// Directory names are unchanged. Just append.
func (f *Fs) addDir(entries *fs.DirEntries, dir fs.Directory) {
	*entries = append(*entries, f.newDir(dir))
}

// Processes file entries by removing compression data. Don't ask me how it works. I don't know.
func (f *Fs) processEntries(entries fs.DirEntries) (newEntries fs.DirEntries, err error) {
	newEntries = entries[:0] // in place filter
	for _, entry := range entries {
		switch x := entry.(type) {
		case fs.Object:
			if isMetadataFile(x.Remote()) // Only care about metadata files; non-metadata files are redundant.
				f.add(&newEntries, x)
		case fs.Directory:
			f.addDir(&newEntries, x)
		default:
			return nil, errors.Errorf("Unknown object type %T", entry)
		}
	}
	return newEntries, nil
}

// List the objects and directories in dir into entries.  The
// entries can be returned in any order but should be for a
// complete directory.
//
// dir should be "" to list the root, and should not have
// trailing slashes.
//
// This should return ErrDirNotFound if the directory isn't
// found.
// List entries and process them
func (f *Fs) List(dir string) (entries fs.DirEntries, err error) {
	entries, err = f.Fs.List(dir)
	if err != nil {
		return nil, err
	}
	return f.processEntries(entries)
}

// ListR lists the objects and directories of the Fs starting
// from dir recursively into out.
//
// dir should be "" to start from the root, and should not
// have trailing slashes.
//
// This should return ErrDirNotFound if the directory isn't
// found.
//
// It should call callback for each tranche of entries read.
// These need not be returned in any particular order.  If
// callback returns an error then the listing will stop
// immediately.
//
// Don't implement this unless you have a more efficient way
// of listing recursively that doing a directory traversal.
func (f *Fs) ListR(dir string, callback fs.ListRCallback) (err error) {
	return f.Fs.Features().ListR(dir, func(entries fs.DirEntries) error {
		newEntries, err := f.processEntries(entries)
		if err != nil {
			return err
		}
		return callback(newEntries)
	})
}

// NewObject finds the Object at remote.
func (f *Fs) NewObject(remote string) (fs.Object, error) {
	// Read metadata from metadata object
	meta := readMetadata(generateMetadataName(remote))
	if meta == nil {
		return nil, ErrDecodingMetadata
	}
	// Create our Object
	o = f.Fs.NewObject(meta.filename)
	return f.newObject(o, mo, meta), nil
}

type putFn func(in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error)

// Put a compressed version of a file
func (f *Fs) putCompress(in io.Reader, src fs.ObjectInfo, options []fs.OpenOption, put putFn) (fs.Object, *ObjectMetadata, error) {
	// Unwrap reader accounting
	in, wrap := accounting.UnWrap(in)

	// Compress the file
	var wrappedIn io.Reader
	pipeReader, pipeWriter := io.Pipe()
	compressionError := make(chan error)
	blockDataResult := make(chan []uint32)
	go func() {
		blockData, err := f.c.CompressFileReturningBlockData(in, pipeWriter)
		closeErr := pipeWriter.Close()
		if closeErr != nil {
			fs.Errorf(nil, "Failed to close compression pipe: %v", err)
			if err == nil {
				err = closeErr
			}
		}
		compressionError <- err
		blockDataResult <- blockData
	}()
	wrappedIn = wrap(bufio.NewReaderSize(pipeReader, bufferSize)) // Bufio required for multithreading

	// Find a hash the destination supports to compute a hash of
	// the compressed data. Also intialize metadata hasher.
	ht := f.Fs.Hashes().GetOne()
	var hasher *hash.MultiHasher
	var err error
	metaHasher := md5.New()
	// unwrap the accounting
	var wrap accounting.WrapFn
	wrappedIn, wrap = accounting.UnWrap(wrappedIn)
	if ht != hash.None {
		hasher, err = hash.NewMultiHasherTypes(hash.NewHashSet(ht))
		if err != nil {
			return nil, nil, err
		}
		// add the hasher
		wrappedIn = io.TeeReader(wrappedIn, hasher)
	}
	// Add the metadata hasher
	wrappedIn = io.TeeReader(wrappedIn, metaHasher)
	// wrap the accounting back on
	wrappedIn = wrap(wrappedIn)

	// Transfer the data
	o, err := put(wrappedIn, f.renameObjectInfo(src, f.c.generateDataName(src.Remote())), options...)
	if err != nil {
		removeErr := o.Remove()
		if removeErr != nil {
			fs.Errorf(o, "Failed to remove partially transferred object: %v", err)
		}
		return nil, nil, err
	}

	// Check whether we got an error during compression
	err = <-compressionError
	if err != nil {
		removeErr := o.Remove()
		if removeErr != nil {
			fs.Errorf(o, "Failed to remove partially transferred object: %v", err)
		}
		return nil, nil, err
	}

	// Generate metadata
	blockData := <- blockDataResult
	meta := generateMetadata(o.Size(), f.c.CompressionMode, f.c.generateDataName(src.Remote()), blockData, metaHasher.Sum())

	// Check the hashes of the compressed data if we were comparing them
	if ht != hash.None && hasher != nil {
		srcHash := hasher.Sums()[ht]
		var dstHash string
		dstHash, err = o.Hash(ht)
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to read destination hash")
		}
		if srcHash != "" && dstHash != "" && srcHash != dstHash {
			// remove object
			err = o.Remove()
			if err != nil {
				fs.Errorf(o, "Failed to remove corrupted object: %v", err)
			}
			return nil, nil, errors.Errorf("corrupted on transfer: %v compressed hashes differ %q vs %q", ht, srcHash, dstHash)
		}
	}

	return f.newObject(o), meta, nil
}

// Put an uncompressed version of a file
func (f *Fs) putUncompress(in io.Reader, src fs.ObjectInfo, options []fs.OpenOption, put putFn) (fs.Object, *ObjectMetadata, error) {
	// Unwrap the accounting, add our metadata hasher, then wrap it back on
	in, wrap := accounting.UnWrap(in)
	metaHasher := md5.New()
	in = io.TeeReader(in, metaHasher)
	in = wrap(in)
	// Put the object
	o, err := put(in, src, options...)
	if err != nil {
		removeErr := o.Remove()
		if removeErr != nil {
			fs.Errorf(o, "Failed to remove partially transferred object: %v", err)
		}
		return nil, nil, err
	}
	// Return our object and metadata
	return o, generateMetadata(o.Size(), Uncompressed, src.Remote(), []byte{}, metaHasher.Sum()), nil
}

// This function will write a metadata struct to a metadata Object
func (f *Fs) putMetadata(meta *ObjectMetadata) (mo fs.Object, err error) {
	var b bytes.Buffer
	gzipWriter, err := gzip.NewWriter(&b)
	if err != nil {
		return nil
	}
	metadataEncoder := gob.NewEncoder(gzipWriter)
	metadataEncoder.Encode(meta)
	err = gzipWriter.Close()
	if err != nil {
		return nil
	}
	f.Fs.Put(bytes.NewReader(b.Bytes()), // I need some way to actually be able to put this by getting an ObjectInfo src somehow
}

// Put in to the remote path with the modTime given of the given size
//
// May create the object even if it returns an error - if so
// will return the object and the error, otherwise will return
// nil and the error
func (f *Fs) Put(in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	return f.put(in, src, options, f.Fs.Put)
}

// PutStream uploads to the remote path with the modTime given of indeterminate size
func (f *Fs) PutStream(in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	return f.put(in, src, options, f.Fs.Features().PutStream)
}

// Hashes returns the supported hash sets.
func (f *Fs) Hashes() hash.Set {
	return hash.Set(hash.None)
}

// Mkdir makes the directory (container, bucket)
//
// Shouldn't return an error if it already exists
func (f *Fs) Mkdir(dir string) error {
	return f.Fs.Mkdir(dir)
}

// Rmdir removes the directory (container, bucket) if empty
//
// Return an error if it doesn't exist or isn't empty
func (f *Fs) Rmdir(dir string) error {
	return f.Fs.Rmdir(dir)
}

// Purge all files in the root and the root directory
//
// Implement this if you have a way of deleting all the files
// quicker than just running Remove() on the result of List()
//
// Return an error if it doesn't exist
func (f *Fs) Purge() error {
	do := f.Fs.Features().Purge
	if do == nil {
		return fs.ErrorCantPurge
	}
	return do()
}

// Copy src to this remote using server side copy operations.
//
// This is stored with the remote path given
//
// It returns the destination Object and a possible error
//
// Will only be called if src.Fs().Name() == f.Name()
//
// If it isn't possible then return fs.ErrorCantCopy
func (f *Fs) Copy(src fs.Object, remote string) (fs.Object, error) {
	do := f.Fs.Features().Copy
	if do == nil {
		return nil, fs.ErrorCantCopy
	}
	o, ok := src.(*Object)
	if !ok {
		return nil, fs.ErrorCantCopy
	}
	newFilename := f.c.generateFileNameFromName(remote)
	oResult, err := do(o.Object, newFilename)
	if err != nil {
		return nil, err
	}
	return f.newObject(oResult), nil
}

// Move src to this remote using server side move operations.
//
// This is stored with the remote path given
//
// It returns the destination Object and a possible error
//
// Will only be called if src.Fs().Name() == f.Name()
//
// If it isn't possible then return fs.ErrorCantMove
func (f *Fs) Move(src fs.Object, remote string) (fs.Object, error) {
	do := f.Fs.Features().Move
	if do == nil {
		return nil, fs.ErrorCantMove
	}
	o, ok := src.(*Object)
	if !ok {
		return nil, fs.ErrorCantMove
	}
	newFilename := f.c.generateFileNameFromName(remote)
	oResult, err := do(o.Object, newFilename)
	if err != nil {
		return nil, err
	}
	return f.newObject(oResult), nil
}

// DirMove moves src, srcRemote to this remote at dstRemote
// using server side move operations.
//
// Will only be called if src.Fs().Name() == f.Name()
//
// If it isn't possible then return fs.ErrorCantDirMove
//
// If destination exists then return fs.ErrorDirExists
func (f *Fs) DirMove(src fs.Fs, srcRemote, dstRemote string) error {
	do := f.Fs.Features().DirMove
	if do == nil {
		return fs.ErrorCantDirMove
	}
	srcFs, ok := src.(*Fs)
	if !ok {
		fs.Debugf(srcFs, "Can't move directory - not same remote type")
		return fs.ErrorCantDirMove
	}
	return do(srcFs.Fs, srcRemote, dstRemote)
}

// PutUnchecked uploads the object
//
// This will create a duplicate if we upload a new file without
// checking to see if there is one already - use Put() for that.
func (f *Fs) PutUnchecked(in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	// Unwrap reader accounting
	in, wrap := accounting.UnWrap(in)

	// Check if putUnchecked is supported
	do := f.Fs.Features().PutUnchecked
	if do == nil {
		return nil, errors.New("can't PutUnchecked")
	}

	// Unwrap reader accounting and decompress file
	var wrappedIn io.Reader
	pipeReader, pipeWriter := io.Pipe()
	compressionError := make(chan error)
	go func() {
		err := f.c.CompressFileAppendingBlockData(in, pipeWriter)
		compressionError <- err
	}()
	wrappedIn = wrap(bufio.NewReaderSize(pipeReader, bufferSize)) // Required for multithreading

	// Actually put the file
	o, err := do(wrappedIn, f.newObjectInfo(src))
	if err != nil {
		return nil, err
	}

	// Check for errors
	err = <-compressionError
	if err != nil {
		return nil, err
	}
	return f.newObject(o), nil
}

// CleanUp the trash in the Fs
//
// Implement this if you have a way of emptying the trash or
// otherwise cleaning up old versions of files.
func (f *Fs) CleanUp() error {
	do := f.Fs.Features().CleanUp
	if do == nil {
		return errors.New("can't CleanUp")
	}
	return do()
}

// About gets quota information from the Fs
func (f *Fs) About() (*fs.Usage, error) {
	do := f.Fs.Features().About
	if do == nil {
		return nil, errors.New("About not supported")
	}
	return do()
}

// UnWrap returns the Fs that this Fs is wrapping
func (f *Fs) UnWrap() fs.Fs {
	return f.Fs
}

// WrapFs returns the Fs that is wrapping this Fs
func (f *Fs) WrapFs() fs.Fs {
	return f.wrapper
}

// SetWrapper sets the Fs that is wrapping this Fs
func (f *Fs) SetWrapper(wrapper fs.Fs) {
	f.wrapper = wrapper
}

// MergeDirs merges the contents of all the directories passed
// in into the first one and rmdirs the other directories.
func (f *Fs) MergeDirs(dirs []fs.Directory) error {
	do := f.Fs.Features().MergeDirs
	if do == nil {
		return errors.New("MergeDirs not supported")
	}
	out := make([]fs.Directory, len(dirs))
	for i, dir := range dirs {
		out[i] = fs.NewDirCopy(dir).SetRemote(dir.Remote())
	}
	return do(out)
}

// DirCacheFlush resets the directory cache - used in testing
// as an optional interface
func (f *Fs) DirCacheFlush() {
	do := f.Fs.Features().DirCacheFlush
	if do != nil {
		do()
	}
}

// ChangeNotify calls the passed function with a path
// that has had changes. If the implementation
// uses polling, it should adhere to the given interval.
func (f *Fs) ChangeNotify(notifyFunc func(string, fs.EntryType), pollIntervalChan <-chan time.Duration) {
	do := f.Fs.Features().ChangeNotify
	if do == nil {
		return
	}
	wrappedNotifyFunc := func(path string, entryType fs.EntryType) {
		fs.Logf(f, "path %q entryType %d", path, entryType)
		var (
			wrappedPath string
		)
		switch entryType {
		case fs.EntryDirectory:
			wrappedPath = path
		case fs.EntryObject:
			wrappedPath = f.c.generateFileNameFromName(path)
		default:
			fs.Errorf(path, "press ChangeNotify: ignoring unknown EntryType %d", entryType)
			return
		}
		notifyFunc(wrappedPath, entryType)
	}
	do(wrappedNotifyFunc, pollIntervalChan)
}

// PublicLink generates a public link to the remote path (usually readable by anyone)
func (f *Fs) PublicLink(remote string) (string, error) {
	do := f.Fs.Features().PublicLink
	if do == nil {
		return "", errors.New("PublicLink not supported")
	}
	o, err := f.NewObject(remote)
	if err != nil {
		// assume it is a directory
		return do(remote)
	}
	return do(o.(*Object).Object.Remote())
}

/*** OBJECT FUNCTIONS ***/

// ObjectMetadata describes the metadata for an Object.
type ObjectMetadata struct {
	size int64 // Uncompressed size of the file.
	compressionMode int // Compression mode of the file.
	filename string // Name of the file containing the actual data, compressed or uncompressed.
	blockData []uint32 // Block indexing data for the file.
	hash []byte // MD5 hash of the file.
}

// Object with external metadata
type Object struct {
	f *Fs // Filesystem object is in
	mo fs.Object // Metadata object for this object
	data fs.Object // Data object for this object
	meta ObjectMetadata // Metadata struct for this object
}

// This function generates a metadata object
func generateMetadata(size int64, compressionMode int, filename string, blockData []uint32, hash []byte) *ObjectMetadata {
	meta := new(ObjectMetadata)
	meta.size = size
	meta.compressionMode = compressionMode
	meta.filename = filename
	meta.blockData = blockData
	meta.hash = hash
	return meta
}

// This function will generate a metadata filename
func generateMetaFilename(meta *ObjectMetadata) (metaFileName string, err error) {
	if meta.compressionMode == Uncompressed {
		metaFileName = meta.filename + metaFileExt
	} else {
		origFileName, _, err := processFileName(meta.filename)
		if err != nil {
			return "", err
		}
		metaFileName = origFileName + metaFileExt
	}
	return metaFileName
}

// This function will read the metadata from a metadata object.
func readMetadata(mo fs.Object) (meta *ObjectMetadata) {
	meta = new(ObjectMetadata)
	rc, err := mo.Open()
	if err != nil {
		return nil
	}
	gzipReader, err := gzip.NewReader(rc)
	if err != nil {
		return nil
	}
	metadataDecoder := gob.NewDecoder(gzipReader)
	metadataDecoder.Decode(meta)
	err = rc.Close()
	if err != nil {
		return nil
	}
	err = gzipReader.Close()
	if err != nil {
		return nil
	}
	return meta
}

// This will initialize the variables of a new press Object. The metadata object, mo, and metadata struct, meta, must be specified.
func (f *Fs) newObject(o fs.Object, mo fs.Object, meta ObjectMetadata) *Object {
	return &Object{
		Object: o,
		f:      f,
		mo:    mo,
		meta: meta,
	}
}

// Fs returns read only access to the Fs that this object is part of
func (o *Object) Fs() fs.Info {
	return o.f
}

// Return a string version
func (o *Object) String() string {
	if o == nil {
		return "<nil>"
	}
	return o.Remote()
}

// Remove removes this object
func (o *Object) Remove() error {
	o.mo.Remove()
	return o.Object.Remove()
}

// Remote returns the remote path
func (o *Object) Remote() string {
	remote := o.Object.Remote()
	filename, _, err := processFileName(remote)
	if err != nil {
		fs.Errorf(o, "Error on getting remote path: %v", err)
		return remote
	}
	return filename
}

// Size returns the size of the file
func (o *Object) Size() int64 {
	return o.meta.size
}

// Hash returns the selected checksum of the file
// If no checksum is available it returns ""
func (o *Object) Hash(ht hash.Type) (string, error) {
	if ht & hash.MD5 == 0 {
		return "", hash.ErrUnsupported
	} else {
		return hex.EncodeToString(o.meta.hash)
	}
}

// UnWrap returns the wrapped Object
func (o *Object) UnWrap() fs.Object {
	return o.Object
}

// ReadCloserWrapper combines a Reader and a Closer to a ReadCloser
type ReadCloserWrapper struct {
	dataSource io.Reader
	closer     io.Closer
}

func combineReaderAndCloser(dataSource io.Reader, closer io.Closer) *ReadCloserWrapper {
	rc := new(ReadCloserWrapper)
	rc.dataSource = dataSource
	rc.closer = closer
	return rc
}

// Read function
func (w *ReadCloserWrapper) Read(p []byte) (n int, err error) {
	return w.dataSource.Read(p)
}

// Close function
func (w *ReadCloserWrapper) Close() error {
	return w.closer.Close()
}

// Open opens the file for read.  Call Close() on the returned io.ReadCloser. Note that this call requires quite a bit of overhead.
func (o *Object) Open(options ...fs.OpenOption) (rc io.ReadCloser, err error) {
	// Get offset and limit from OpenOptions, pass the rest to the underlying remote
	var openOptions []fs.OpenOption = []fs.OpenOption{&fs.SeekOption{Offset: 0}}
	var offset, limit int64 = 0, -1
	for _, option := range options {
		switch x := option.(type) {
		case *fs.SeekOption:
			offset = x.Offset
		case *fs.RangeOption:
			offset, limit = x.Decode(o.Size())
		default:
			openOptions = append(openOptions, option)
		}
	}
	// Get a chunkedreader for the wrapped object
	chunkedReader := chunkedreader.New(o.Object, initialChunkSize, maxChunkSize)
	// Get file handle
	FileHandle, _, err := o.f.c.DecompressFile(chunkedReader, o.Object.Size())
	if err != nil {
		return nil, err
	}
	// Seek and limit according to the options given
	_, err = FileHandle.Seek(offset, io.SeekStart)
	if err != nil {
		return nil, err
	}
	var fileReader io.Reader
	if limit != -1 {
		fileReader = io.LimitReader(FileHandle, limit)
	} else {
		fileReader = FileHandle
	}
	// Return a ReadCloser
	return combineReaderAndCloser(fileReader, chunkedReader), nil
}

// Update in to the object with the modTime given of the given size
func (o *Object) Update(in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	update := func(in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
		return o.Object, o.Object.Update(in, src, options...)
	}
	// We have to force a compression mode here so that it updates instead of writing a new file
	_, err := o.f.put(in, src, options, update, o.meta.compressionMode)
	return err
}

// ID returns the ID of the Object if known, or "" if not
func (o *Object) ID() string {
	do, ok := o.Object.(fs.IDer)
	if !ok {
		return ""
	}
	return do.ID()
}

// SetTier performs changing storage tier of the Object if
// multiple storage classes supported
func (o *Object) SetTier(tier string) error {
	do, ok := o.Object.(fs.SetTierer)
	if !ok {
		return errors.New("press: underlying remote does not support SetTier")
	}
	return do.SetTier(tier)
}

// GetTier returns storage tier or class of the Object
func (o *Object) GetTier() string {
	do, ok := o.Object.(fs.GetTierer)
	if !ok {
		return ""
	}
	return do.GetTier()
}

// Renames an ObjectInfo
type RenamedObjectInfo struct {
	fs.ObjectInfo
	remote string
}
func (f *Fs) renameObjectInfo(src fs.ObjectInfo, newRemote string) *RenamedObjectInfo {
	return &ObjectInfo{
		ObjectInfo: src,
		remote: newRemote,
	}
}
func (o *RenamedObjectInfo) Remote() string {
	return o.remote
}

// ObjectInfo describes a wrapped fs.ObjectInfo for being the source
type ObjectInfo struct {
	fs.ObjectInfo
	f *Fs
	meta ObjectMetadata
}

// Gets a new ObjectInfo from an src and a metadata struct
func (f *Fs) newObjectInfo(src fs.ObjectInfo, meta *ObjectMetadata) *ObjectInfo {
	return &ObjectInfo{
		ObjectInfo: src,
		f:          f,
		meta:       meta
	}
}

// Fs returns read only access to the Fs that this object is part of
func (o *ObjectInfo) Fs() fs.Info {
	return o.f
}

// Remote returns the remote path
func (o *ObjectInfo) Remote() string {
	origFileName, _, _ = processFileName(o.filename)
	return origFileName
}

// Size returns the size of the file
func (o *ObjectInfo) Size() int64 {
	return o.meta.size
}

// Hash returns the selected checksum of the file
// If no checksum is available it returns ""
func (o *ObjectInfo) Hash(ht hash.Type) (string, error) {
	if ht & hash.MD5 == 0 {
		return "", hash.ErrUnsupported
	} else {
		return hex.EncodeToString(o.meta.hash)
	}
}

// Check the interfaces are satisfied
var (
	_ fs.Fs              = (*Fs)(nil)
	_ fs.Purger          = (*Fs)(nil)
	_ fs.Copier          = (*Fs)(nil)
	_ fs.Mover           = (*Fs)(nil)
	_ fs.DirMover        = (*Fs)(nil)
	_ fs.PutUncheckeder  = (*Fs)(nil)
	_ fs.PutStreamer     = (*Fs)(nil)
	_ fs.CleanUpper      = (*Fs)(nil)
	_ fs.UnWrapper       = (*Fs)(nil)
	_ fs.ListRer         = (*Fs)(nil)
	_ fs.Abouter         = (*Fs)(nil)
	_ fs.Wrapper         = (*Fs)(nil)
	_ fs.MergeDirser     = (*Fs)(nil)
	_ fs.DirCacheFlusher = (*Fs)(nil)
	_ fs.ChangeNotifier  = (*Fs)(nil)
	_ fs.PublicLinker    = (*Fs)(nil)
	_ fs.ObjectInfo      = (*ObjectInfo)(nil)
	_ fs.Object          = (*Object)(nil)
	_ fs.ObjectUnWrapper = (*Object)(nil)
	_ fs.IDer            = (*Object)(nil)
	_ fs.SetTierer       = (*Object)(nil)
	_ fs.GetTierer       = (*Object)(nil)
)
