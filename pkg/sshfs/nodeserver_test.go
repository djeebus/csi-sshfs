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
	t.Run("private key example", func(t *testing.T) {
		result := generateMountArgs("user", "host", "port", "directory", "target", "", "private-key", "ssh-opt1;ssh-opt2=hello world")
		require.Equal(t, []string{
			"user@host:directory", "target",
			"-o", "IdentityFile=private-key",
			"-o", "ServerAliveCountMax=3",
			"-o", "ServerAliveInterval=15",
			"-o", "StrictHostKeyChecking=accept-new",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "allow_other",
			"-o", "gid=0",
			"-o", "port=port",
			"-o", "reconnect",
			"-o", "ssh-opt1",
			"-o", "ssh-opt2=hello world",
			"-o", "uid=100",
		}, result)
	})

	t.Run("password example", func(t *testing.T) {
		result := generateMountArgs("user", "host", "port", "directory", "target", "a-password", "", "ssh-opt1;ssh-opt2=hello world")
		require.Equal(t, []string{
			"user@host:directory", "target",
			"-o", "ServerAliveCountMax=3",
			"-o", "ServerAliveInterval=15",
			"-o", "StrictHostKeyChecking=accept-new",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "allow_other",
			"-o", "gid=0",
			"-o", "password_stdin",
			"-o", "port=port",
			"-o", "reconnect",
			"-o", "ssh-opt1",
			"-o", "ssh-opt2=hello world",
			"-o", "uid=100",
		}, result)
	})

	t.Run("can override defaults", func(t *testing.T) {
		result := generateMountArgs("user", "host", "port", "directory", "target", "a-password", "", "uid=33;gid=33")
		require.Equal(t, []string{
			"user@host:directory", "target",
			"-o", "ServerAliveCountMax=3",
			"-o", "ServerAliveInterval=15",
			"-o", "StrictHostKeyChecking=accept-new",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "allow_other",
			"-o", "gid=33",
			"-o", "password_stdin",
			"-o", "port=port",
			"-o", "reconnect",
			"-o", "uid=33",
		}, result)
	})

}
