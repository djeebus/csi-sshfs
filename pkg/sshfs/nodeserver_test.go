package sshfs

import (
    "testing"

    "github.com/stretchr/testify/require"
)

func TestParseRawOpts(t *testing.T) {
    t.Run("can omit private key", func(t *testing.T) {
        results := parseRawOpts("")
        require.Equal(t, map[string]string{}, results)
    })
}

func TestGenerateMountArgs(t *testing.T) {
    t.Run("private key example", func(t *testing.T) {
        config := config{"host", "port", "directory", map[string]string{"ssh-opt1": "", "ssh-opt2": "hello world"}, "user", "", "private-key"}
        result := generateMountArgs(config, "target")
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
        config := config{"host", "port", "directory", map[string]string{"ssh-opt1": "", "ssh-opt2": "hello world"}, "user", "p4ssw0rd", ""}
        result := generateMountArgs(config, "target")
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
        config := config{"host", "port", "directory", map[string]string{"gid": "33", "uid": "33"}, "user", "password", ""}
        result := generateMountArgs(config, "target")
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
