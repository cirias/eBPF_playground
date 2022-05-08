package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"

	"github.com/dustin/go-humanize"
)

const (
	bpfFSPath = "/sys/fs/bpf"
)

var (
	ifce      = flag.String("interface", "wlp0s20f3", "name of interface to monitor")
	direction = flag.String("direction", "ingress", "direction of the traffic, ingress or egress")
	interval  = flag.Int("interval", 1, "interval in seconds for each output")
	duration  = flag.Int("duration", 2, "output speed instead of amount, when non-zero duration is given. specified the duration in seconds to divide the amount")
)

func main() {
	flag.Parse()

	if err := watch(*ifce); err != nil {
		log.Fatal(err)
	}
}

func watch(ifname string) error {
	pinPath := path.Join(bpfFSPath, "ifstats")
	if err := os.MkdirAll(pinPath, os.ModePerm); err != nil {
		log.Fatalf("failed to create bpf fs subpath: %+v", err)
	}
	defer os.Remove(pinPath)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			// Pin the map to the BPF filesystem and configure the
			// library to automatically re-write it in the BPF
			// program so it can be re-used if it already exists or
			// create it if not
			PinPath: pinPath,
		},
	}); err != nil {
		return fmt.Errorf("loading objects: %v", err)
	}
	defer objs.Close()

	dev, err := netlink.LinkByName(ifname)
	if err != nil {
		return fmt.Errorf("failed to lookup device %q: %s", ifname, err)
	}

	qdiscAttrs := netlink.QdiscAttrs{
		LinkIndex: dev.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: qdiscAttrs,
		QdiscType:  "clsact",
	}
	if err = netlink.QdiscAdd(qdisc); err != nil {
		return fmt.Errorf("failed to create clsact qdisc on %q: %s", ifname, err)
	}
	defer func() {
		if err := netlink.QdiscDel(qdisc); err != nil {
			log.Printf("failed to delete clsact qdisc on %q: %s", ifname, err)
		}
	}()

	var parentID uint32 = netlink.HANDLE_MIN_INGRESS
	if *direction == "egress" {
		parentID = netlink.HANDLE_MIN_EGRESS
	}

	filterAttrs := netlink.FilterAttrs{
		LinkIndex: dev.Attrs().Index,
		Parent:    parentID,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  3,
		Priority:  1,
	}
	filter := &netlink.BpfFilter{
		FilterAttrs:  filterAttrs,
		Fd:           objs.bpfPrograms.ClsMain.FD(),
		Name:         "polEntry",
		DirectAction: true,
	}
	if err = netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("failed to create egress filter on %q: %s", ifname, err)
	}
	defer func() {
		if err = netlink.FilterDel(filter); err != nil {
			log.Printf("failed to delete egress filter on %q: %s", ifname, err)
		}
	}()

	ticker := time.NewTicker(time.Duration(*interval) * time.Second)
	defer ticker.Stop()

	errCh := make(chan error)
	go func() (err error) {
		defer func() {
			if err != nil {
				errCh <- err
			}
		}()

		fmt.Printf("%25s%25s%25s\n", "TCP", "UDP", "Others")

		var value struct {
			Packets uint32
			Bytes   uint32
		}
		rings := make([]*struct {
			Packets *Ring
			Bytes   *Ring
		}, 3)
		for i := range rings {
			rings[i] = &struct {
				Packets *Ring
				Bytes   *Ring
			}{
				Packets: NewRing(*duration + 1),
				Bytes:   NewRing(*duration + 1),
			}
		}
		for range ticker.C {
			for i, r := range rings {
				if err := objs.bpfMaps.MapStats.Lookup(uint32(i), &value); err != nil {
					return fmt.Errorf("could not read map: %w", err)
				}
				r.Packets.Push(value.Packets)
				r.Bytes.Push(value.Bytes)

				fmt.Printf("%14s/s %4d p/s", humanize.Bytes(uint64(r.Bytes.Diff())/uint64(*duration)), r.Packets.Diff()/uint32(*duration))
			}
			fmt.Println()
		}
		return nil
	}()

	quit := make(chan os.Signal, 1)
	// kill (no param) default send syscanll.SIGTERM
	// kill -2 is syscall.SIGINT
	// kill -9 is syscall.SIGKILL but can"t be catch, so don't need add it
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-quit:
	case err := <-errCh:
		log.Println(err)
	}

	log.Println("Stop..")

	return nil
}

type Ring struct {
	i    int // write offset
	data []uint32
}

func NewRing(n int) *Ring {
	return &Ring{i: 0, data: make([]uint32, n)}
}

func (r *Ring) Push(v uint32) {
	r.data[r.i] = v
	r.i = (r.i + 1) % len(r.data)
}

func (r *Ring) Diff() uint32 {
	return r.Latest() - r.Earliest()
}

func (r *Ring) Earliest() uint32 {
	return r.data[r.i]
}

func (r *Ring) Latest() uint32 {
	i := (len(r.data) + r.i - 1) % len(r.data)
	return r.data[i]
}
