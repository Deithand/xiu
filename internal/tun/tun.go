package tun

import (
	"fmt"
	"os/exec"

	"github.com/songgao/water"
)

// Create creates TUN interface with given name and mtu.
func Create(name string, mtu int) (*water.Interface, error) {
	cfg := water.Config{DeviceType: water.TUN}
	cfg.Name = name
	iface, err := water.New(cfg)
	if err != nil {
		return nil, err
	}
	if mtu > 0 {
		exec.Command("ip", "link", "set", "dev", iface.Name(), "mtu", fmt.Sprint(mtu)).Run()
	}
	exec.Command("ip", "link", "set", "dev", iface.Name(), "up").Run()
	return iface, nil
}

// AddRoute adds route via interface.
func AddRoute(cidr, dev string) error {
	cmd := exec.Command("ip", "route", "add", cidr, "dev", dev)
	return cmd.Run()
}
