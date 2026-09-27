package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

// Event description C-structure analog
type FimEvent struct {
	EventType uint32    // type of event
	Uid       uint32    // user identifier
	Pid       uint32    // process identifier
	Filename  [256]byte // name of file, connected with event
}

const (
	FIM_MODIFY = 1 << 0 // modification
	FIM_ATTRIB = 1 << 1 // attributes change
	FIM_DELETE = 1 << 2 // self deletion
	FIM_MOVE   = 1 << 3 // self movement
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

	// 2.Attach kprobes
	kpWrite, err := link.Kprobe("vfs_write", objs.TraceVfsWrite, nil)
	if err != nil {
		log.Fatal("Attaching kprobe vfs_write:", err)
	}
	defer kpWrite.Close()

	kpAttr, err := link.Kprobe("notify_change", objs.TraceSetattr, nil)
	if err != nil {
		log.Fatal("Attaching kprobe notify_change:", err)
	}
	defer kpAttr.Close()

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
	fmt.Printf("FIM eBPF monitor started on %s (inode=%d). Press Ctrl+C to stop.\n",
		watchPath, ino)

	go func() {
		var event FimEvent
		for {
			record, err := events.Read()
			if err != nil {
				log.Println("Reading from perf buffer:", err)
				continue
			}

			if err := binary.Read(bytes.NewBuffer(record.RawSample),
				binary.LittleEndian, &event); err != nil {
				log.Println("Parsing event:", err)
				continue
			}

			// 6.Handle event (analog of your handler for fanotify)
			handleEvent(event)
		}
	}()

	<-sig
	fmt.Println("\nShutting down...")
}

func handleEvent(e FimEvent) {
	eventStr := getEventType(e.EventType)
	filename := string(bytes.TrimRight(e.Filename[:], "\x00"))

	fmt.Printf("[%s] PID=%d UID=%d FILE=%s\n",
		eventStr, e.Pid, e.Uid, filename)
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
	default:
		return "UNKNOWN"
	}
}
