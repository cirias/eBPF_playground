```
sudo tc qdisc add dev wlp0s20f3 handle ffff: clsact

sudo tc filter add dev wlp0s20f3 parent ffff:fff3 bpf obj bpf_bpfel.o sec tc da

tc filter show dev wlp0s20f3 egress

tc qdisc show dev wlp0s20f3

sudo tc filter del dev wlp0s20f3 parent ffff:fff3

sudo tc qdisc del dev wlp0s20f3 handle ffff: clsact
```
