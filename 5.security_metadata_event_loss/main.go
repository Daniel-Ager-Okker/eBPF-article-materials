package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/pprof"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

// Event description C-structure analog
type FimEvent struct {
	Ino       uint64    // inode of the event object (0 for CREATE_IN)
	ParentIno uint64    // inode of the directory the event happened in
	EventType uint32    // type of event
	Uid       uint32    // user identifier
	Pid       uint32    // process identifier
	Filename  [256]byte // name of file, connected with event
}

const (
	FIM_MODIFY    = 1 << 0 // modification
	FIM_ATTRIB    = 1 << 1 // attributes change
	FIM_DELETE    = 1 << 2 // self deletion
	FIM_MOVE      = 1 << 3 // self movement
	FIM_CREATE_IN = 1 << 4 // creation inside the directory
	FIM_DELETE_IN = 1 << 5 // deletion inside the directory
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang fim fim.bpf.c -- -I. -O2 -g -target bpf -D__TARGET_ARCH_x86

func main() {
	// 0.Start CPU profiling (go tool pprof cpu.out)
	stopCPUProfile := startCPUProfile()
	defer stopCPUProfile()

	watchPath, rootIno := parseWatchTarget()

	// 1.Load BPF program
	objs := loadBPFProgram()
	defer objs.Close()

	maxEntries := mapCapacity(objs.WatchedInodes)
	log.Printf("watched_inodes capacity: %d entries", maxEntries)

	// Recursion seed: prime the watched set with the whole existing tree.
	dirPaths, watchCount, skipped := seedWatchTree(&objs, watchPath, rootIno, maxEntries)

	// 2.Attach kprobes
	kprobes := attachKprobes(&objs)
	defer closeLinks(kprobes)

	// 3.Read events through perf buffer
	events := newPerfReader(objs)
	defer events.Close()

	// 4.Handle termination signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	// 5.Start monitoring
	fmt.Printf("FIM eBPF monitor started on directory %s (inode=%d, watching %d inodes, skipped %d entries). Press Ctrl+C to stop.\n",
		watchPath, rootIno, watchCount, skipped)

	go processEvents(events, &objs, dirPaths)

	<-sig
	fmt.Println("\nShutting down...")
}

// Start CPU profiling into cpu.out and return a stop function.
func startCPUProfile() (stop func()) {
	f, err := os.Create("cpu.out")
	if err != nil {
		log.Fatal("could not create CPU profile: ", err)
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		log.Fatal("could not start CPU profile: ", err)
	}
	return func() {
		pprof.StopCPUProfile()
		f.Close()
	}
}

// Validate the CLI argument and resolves the watched directory to its inode.
func parseWatchTarget() (path string, ino uint64) {
	if len(os.Args) != 2 {
		log.Fatalf("usage: %s <path-to-watch>", os.Args[0])
	}
	watchPath := os.Args[1]

	info, err := os.Stat(watchPath)
	if err != nil {
		log.Fatalf("stat %s: %v", watchPath, err)
	}
	if !info.IsDir() {
		log.Fatalf("%s is not a directory", watchPath)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		log.Fatal("cannot get inode from file stat")
	}
	return watchPath, uint64(stat.Ino)
}

// Load the compiled eBPF objects into the kernel.
func loadBPFProgram() fimObjects {
	var objs fimObjects
	if err := loadFimObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	return objs
}

// Report the max_entries the map was actually created with in the kernel.
func mapCapacity(m *ebpf.Map) uint32 {
	info, err := m.Info()
	if err != nil {
		log.Fatal("Reading watched_inodes info:", err)
	}
	return info.MaxEntries
}

// Walk the whole tree, puts every existing inode into the map and remembers a path for every directory.
func seedWatchTree(objs *fimObjects, watchPath string, rootIno uint64, maxEntries uint32) (dirPaths map[uint64]string, watchCount, skipped int) {
	var one uint8 = 1
	if err := objs.WatchedInodes.Put(rootIno, one); err != nil {
		log.Fatal("Adding watched inode:", err)
	}

	dirPaths = make(map[uint64]string)
	if err := filepath.WalkDir(watchPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Printf("skipping %s: %v", path, err)
			skipped++
			return nil
		}
		info, err := d.Info()
		if err != nil {
			log.Printf("skipping %s: %v", path, err)
			skipped++
			return nil
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}
		childIno := uint64(st.Ino)
		if err := objs.WatchedInodes.Put(childIno, one); err != nil {
			// e.g. the map is full: skip the entry and keep walking
			skipped++
			return nil
		}
		watchCount++
		if d.IsDir() {
			dirPaths[childIno] = path
		}
		return nil
	}); err != nil {
		log.Fatal("Walking watch tree:", err)
	}
	if skipped > 0 {
		log.Printf("warning: %d entries were not watched (map capacity %d)", skipped, maxEntries)
	}
	return dirPaths, watchCount, skipped
}

// Attach every trace program to its kernel symbol and returns the opened links.
func attachKprobes(objs *fimObjects) []link.Link {
	probes := []struct {
		name   string // human-readable label for error messages
		symbol string // kernel function to attach to
		prog   *ebpf.Program
	}{
		{"vfs_write", "vfs_write", objs.TraceVfsWrite},
		{"vfs_write (modify in)", "vfs_write", objs.TraceModifyIn},
		{"notify_change", "notify_change", objs.TraceSetattr},
		{"notify_change (attrib in)", "notify_change", objs.TraceAttribIn},
		{"vfs_unlink", "vfs_unlink", objs.TraceDelete},
		{"vfs_rename", "vfs_rename", objs.TraceMove},
		{"security_inode_create", "security_inode_create", objs.TraceCreateIn},
		{"vfs_mkdir", "vfs_mkdir", objs.TraceMkdirIn},
		{"vfs_unlink (delete in)", "vfs_unlink", objs.TraceDeleteIn},
		{"vfs_rmdir (delete in)", "vfs_rmdir", objs.TraceRmdirIn},
		{"vfs_rmdir (self)", "vfs_rmdir", objs.TraceRmdirSelf},
	}

	links := make([]link.Link, 0, len(probes))
	for _, p := range probes {
		kp, err := link.Kprobe(p.symbol, p.prog, nil)
		if err != nil {
			log.Fatalf("Attaching kprobe %s: %v", p.name, err)
		}
		links = append(links, kp)
	}
	return links
}

// Detache every attached kprobe.
func closeLinks(links []link.Link) {
	for _, l := range links {
		l.Close()
	}
}

// Create the perf buffer reader for events.
func newPerfReader(objs fimObjects) *perf.Reader {
	events, err := perf.NewReader(objs.Events, os.Getpagesize()*64)
	if err != nil {
		log.Fatal("Creating perf reader:", err)
	}
	return events
}

// Read raw records from the perf buffer in a loop, decodes them and dispatches each event.
func processEvents(events *perf.Reader, objs *fimObjects, dirPaths map[uint64]string) {
	var event FimEvent
	for {
		record, err := events.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Println("Reading from perf buffer:", err)
			continue
		}

		if err := decodeEvent(record.RawSample, &event); err != nil {
			log.Println("Parsing event:", err)
			continue
		}

		// 6.Maintain the watched set (recursion), then handle the event
		maintainWatch(objs, dirPaths, event)
		handleEvent(event)
	}
}

// Unmarshal a raw perf sample into a FimEvent.
func decodeEvent(raw []byte, event *FimEvent) error {
	return binary.Read(bytes.NewBuffer(raw), binary.LittleEndian, event)
}

func maintainWatch(objs *fimObjects, dirPaths map[uint64]string, e FimEvent) {
	switch e.EventType {
	case FIM_CREATE_IN:
		watchCreatedEntry(objs, dirPaths, e)
	case FIM_DELETE_IN, FIM_DELETE:
		if err := objs.WatchedInodes.Delete(e.Ino); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			log.Println("Removing watched inode:", err)
		}
		delete(dirPaths, e.Ino)
	}
}

// Stat a freshly created path and adds it to the watched set, so the recursion keeps following newly created directories.
func watchCreatedEntry(objs *fimObjects, dirPaths map[uint64]string, e FimEvent) {
	parentPath, ok := dirPaths[e.ParentIno]
	if !ok {
		return
	}
	name := string(bytes.TrimRight(e.Filename[:], "\x00"))
	if name == "" {
		return
	}
	path := filepath.Join(parentPath, name)

	info, err := lstatWithRetry(path)
	if err != nil {
		// the entry may already be gone (editors churn temp files fast)
		return
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	ino := uint64(st.Ino)
	if err := objs.WatchedInodes.Put(ino, uint8(1)); err != nil {
		// most likely the map is at max_entries: the new object silently
		// drops out of the watched set, is_watched_inode misses it forever
		log.Printf("NOT watching %s (ino=%d): %v", path, ino, err)
		return
	}
	log.Printf("watching %s (ino=%d)", path, ino)
	if info.IsDir() {
		dirPaths[ino] = path
	}
}

// Stat the path with exponential backoff: the kprobe fires at function entry, before the new object is actually on disk.
func lstatWithRetry(path string) (os.FileInfo, error) {
	var info os.FileInfo
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		info, err = os.Lstat(path) // Lstat: do not follow symlinks
		if err == nil {
			break
		}
		time.Sleep(time.Duration(1<<attempt) * time.Millisecond)
	}
	return info, err
}

func handleEvent(e FimEvent) {
	eventStr := getEventType(e.EventType)
	filename := string(bytes.TrimRight(e.Filename[:], "\x00"))

	fmt.Printf("[%s] PID=%d UID=%d INO=%d FILE=%s\n",
		eventStr, e.Pid, e.Uid, e.Ino, filename)
}

func getEventType(etype uint32) string {
	switch etype {
	case FIM_MODIFY:
		return "MODIFY"
	case FIM_ATTRIB:
		return "ATTRIB"
	case FIM_DELETE:
		return "DELETE"
	case FIM_MOVE:
		return "MOVE"
	case FIM_CREATE_IN:
		return "CREATE_IN"
	case FIM_DELETE_IN:
		return "DELETE_IN"
	default:
		return "UNKNOWN"
	}
}
