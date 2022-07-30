package sshfs

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRawOpts(t *testing.T) {
	t.Run("can omit private key", func(t *testing.T) {
		results := make(map[string]string)
		parseRawOpts(results, "")
		require.Equal(t, map[string]string{}, results)
	})
}

func TestGenerateMountArgs(t *testing.T) {
	t.Run("minimal example", func(t *testing.T) {
		result := generateMountArgs("user", "host", "port", "directory", "target", "password", "private-key", "ssh-opt")
		require.Equal(t, []string{
			"user@host:directory", "target",
			"-o", "IdentityFile=private-key",
			"-o", "ServerAliveCountMax=3",
			"-o", "ServerAliveInterval=15",
			"-o", "StrictHostKeyChecking=accept-new",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "allow_other",
			"-o", "gid=0",
			"-o", "password_stdin",
			"-o", "port=port",
			"-o", "reconnect",
			"-o", "ssh-opt",
			"-o", "uid=100",
		}, result)
	})
}
