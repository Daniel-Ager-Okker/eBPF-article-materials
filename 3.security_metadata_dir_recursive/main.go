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
	ino := uint64(stat.Ino)

	// 1.Load BPF program
	objs := fimObjects{}
	if err := loadFimObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	var one uint8 = 1
	if err := objs.WatchedInodes.Put(ino, one); err != nil {
		log.Fatal("Adding watched inode:", err)
	}

	// Recursion seed: walk the whole tree, put every existing inode into the map and remember a path for every directory
	dirPaths := make(map[uint64]string)
	watchCount := 0
	if err := filepath.WalkDir(watchPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}
		childIno := uint64(st.Ino)
		if err := objs.WatchedInodes.Put(childIno, one); err != nil {
			return err
		}
		watchCount++
		if d.IsDir() {
			dirPaths[childIno] = path
		}
		return nil
	}); err != nil {
		log.Fatal("Walking watch tree:", err)
	}

	// 2.Attach kprobes
	kpWrite, err := link.Kprobe("vfs_write", objs.TraceVfsWrite, nil)
	if err != nil {
		log.Fatal("Attaching kprobe vfs_write:", err)
	}
	defer kpWrite.Close()

	kpModifyIn, err := link.Kprobe("vfs_write", objs.TraceModifyIn, nil)
	if err != nil {
		log.Fatal("Attaching kprobe vfs_write (modify in):", err)
	}
	defer kpModifyIn.Close()

	kpAttr, err := link.Kprobe("notify_change", objs.TraceSetattr, nil)
	if err != nil {
		log.Fatal("Attaching kprobe notify_change:", err)
	}
	defer kpAttr.Close()

	kpAttribIn, err := link.Kprobe("notify_change", objs.TraceAttribIn, nil)
	if err != nil {
		log.Fatal("Attaching kprobe notify_change (attrib in):", err)
	}
	defer kpAttribIn.Close()

	kpDelete, err := link.Kprobe("vfs_unlink", objs.TraceDelete, nil)
	if err != nil {
		log.Fatal("Attaching kprobe vfs_unlink:", err)
	}
	defer kpDelete.Close()

	kpMove, err := link.Kprobe("vfs_rename", objs.TraceMove, nil)
	if err != nil {
		log.Fatal("Attaching kprobe vfs_rename:", err)
	}
	defer kpMove.Close()

	kpCreateIn, err := link.Kprobe("security_inode_create", objs.TraceCreateIn, nil)
	if err != nil {
		log.Fatal("Attaching kprobe security_inode_create:", err)
	}
	defer kpCreateIn.Close()

	kpMkdirIn, err := link.Kprobe("vfs_mkdir", objs.TraceMkdirIn, nil)
	if err != nil {
		log.Fatal("Attaching kprobe vfs_mkdir:", err)
	}
	defer kpMkdirIn.Close()

	kpDeleteIn, err := link.Kprobe("vfs_unlink", objs.TraceDeleteIn, nil)
	if err != nil {
		log.Fatal("Attaching kprobe vfs_unlink (delete in):", err)
	}
	defer kpDeleteIn.Close()

	kpRmdirIn, err := link.Kprobe("vfs_rmdir", objs.TraceRmdirIn, nil)
	if err != nil {
		log.Fatal("Attaching kprobe vfs_rmdir (delete in):", err)
	}
	defer kpRmdirIn.Close()

	kpRmdirSelf, err := link.Kprobe("vfs_rmdir", objs.TraceRmdirSelf, nil)
	if err != nil {
		log.Fatal("Attaching kprobe vfs_rmdir (self):", err)
	}
	defer kpRmdirSelf.Close()

	// 3.Read events through perf buffer
	events, err := perf.NewReader(objs.Events, os.Getpagesize()*64)
	if err != nil {
		log.Fatal("Creating perf reader:", err)
	}
	defer events.Close()

	// 4.Handle termination signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	// 5.Start monitoring
	fmt.Printf("FIM eBPF monitor started on directory %s (inode=%d, watching %d inodes). Press Ctrl+C to stop.\n",
		watchPath, ino, watchCount)

	go func() {
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

			if err := binary.Read(bytes.NewBuffer(record.RawSample),
				binary.LittleEndian, &event); err != nil {
				log.Println("Parsing event:", err)
				continue
			}

			// 6.Maintain the watched set (recursion), then handle the event
			maintainWatch(&objs, dirPaths, event)
			handleEvent(event)
		}
	}()

	<-sig
	fmt.Println("\nShutting down...")
}

func maintainWatch(objs *fimObjects, dirPaths map[uint64]string, e FimEvent) {
	switch e.EventType {
	case FIM_CREATE_IN:
		parentPath, ok := dirPaths[e.ParentIno]
		if !ok {
			return
		}
		name := string(bytes.TrimRight(e.Filename[:], "\x00"))
		if name == "" {
			return
		}
		path := filepath.Join(parentPath, name)
		// The kprobe fires at function entry, before the new object is
		// actually on disk, so retry Lstat for a bounded moment
		var info os.FileInfo
		var err error
		for attempt := 0; attempt < 5; attempt++ {
			info, err = os.Lstat(path) // Lstat: do not follow symlinks
			if err == nil {
				break
			}
			time.Sleep(time.Duration(1<<attempt) * time.Millisecond)
		}
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
			log.Println("Adding watched inode:", err)
			return
		}
		if info.IsDir() {
			dirPaths[ino] = path
		}
	case FIM_DELETE_IN, FIM_DELETE:
		if err := objs.WatchedInodes.Delete(e.Ino); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			log.Println("Removing watched inode:", err)
		}
		delete(dirPaths, e.Ino)
	}
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
