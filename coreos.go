package main

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"
)

func (d *Driver) ignitionConfigPath() string {
	machineDir := filepath.Join(d.StorePath, "machines", d.GetMachineName())
	return filepath.Join(machineDir, "ignition.json")
}

func (d *Driver) generateIgnitionConfig() error {
	pubKey, err := ioutil.ReadFile(d.publicSSHKeyPath())
	if err != nil {
		return err
	}

	type ignitionConfigIgnition struct {
		Version string `json:"version"`
	}

	type ignitionConfigPasswdUser struct {
		Name string `json:"name"`
		SshAuthorizedKeys []string `json:"sshAuthorizedKeys"`
	}

	type ignitionConfigPasswd struct {
		Users []ignitionConfigPasswdUser `json:"users"`
	}

	type ignitionConfigSystemdUnit struct {
		Name string `json:"name"`
		Mask bool `json:"mask"`
	}

	type ignitionConfigSystemd struct {
		Units []ignitionConfigSystemdUnit `json:"units"`
	}

	type ignitionConfig struct {
		Ignition ignitionConfigIgnition `json:"ignition"`
		Passwd ignitionConfigPasswd `json:"passwd"`
		Systemd ignitionConfigSystemd `json:"systemd"`
	}

	config := ignitionConfig {
		Ignition: ignitionConfigIgnition { Version: "2.1.0" },
		Passwd: ignitionConfigPasswd {
			Users: []ignitionConfigPasswdUser {
				ignitionConfigPasswdUser {
					Name: defaultSSHUser,
					SshAuthorizedKeys: []string { string(pubKey) },
				},
			},
		},
		Systemd: ignitionConfigSystemd {
			Units: []ignitionConfigSystemdUnit {
				ignitionConfigSystemdUnit {
					Name: "locksmithd.service",
					Mask: true,
				},
				ignitionConfigSystemdUnit {
					Name: "update-engine.service",
					Mask: true,
				},
			},
		},
	}

	c, err := json.Marshal(config)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(d.ignitionConfigPath(), c, 0644)

	return err
}
