package sshfs

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/golang/glog"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/kubernetes/pkg/util/mount"
	"k8s.io/kubernetes/pkg/volume/util"

	csicommon "github.com/kubernetes-csi/drivers/pkg/csi-common"
)

type nodeServer struct {
	*csicommon.DefaultNodeServer
	mounts map[string]*mountPoint
}

type mountPoint struct {
	VolumeId     string
	MountPath    string
	IdentityFile string
}

func (ns *nodeServer) NodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	targetPath := req.GetTargetPath()
	notMnt, e := mount.New("").IsLikelyNotMountPoint(targetPath)
	if e != nil {
		if os.IsNotExist(e) {
			if err := os.MkdirAll(targetPath, 0750); err != nil {
				return nil, status.Error(codes.Internal, err.Error())
			}
			notMnt = true
		} else {
			return nil, status.Error(codes.Internal, e.Error())
		}
	}

	if !notMnt {
		return &csi.NodePublishVolumeResponse{}, nil
	}

	mountOptions := req.GetVolumeCapability().GetMount().GetMountFlags()
	if req.GetReadonly() {
		mountOptions = append(mountOptions, "ro")
	}
	if e := validateVolumeContext(req); e != nil {
		return nil, e
	}

	server := req.GetVolumeContext()["server"]
	port := req.GetVolumeContext()["port"]
	if len(port) == 0 {
		port = "22"
	}

	user := req.GetVolumeContext()["user"]
	ep := req.GetVolumeContext()["share"]
	password := req.GetVolumeContext()["password"]
	privateKey := req.GetVolumeContext()["privateKey"]
	sshOpts := req.GetVolumeContext()["sshOpts"]

	privateKeyPath := ""
	if privateKey != "" {
		secret, e := getPublicKeySecret(privateKey)
		if e != nil {
			return nil, e
		}
		privateKeyPath, e = writePrivateKey(secret)
		if e != nil {
			return nil, e
		}
	}

	e = Mount(user, server, port, ep, targetPath, password, privateKeyPath, sshOpts)
	if e != nil {
		if os.IsPermission(e) {
			return nil, status.Error(codes.PermissionDenied, e.Error())
		}
		if strings.Contains(e.Error(), "invalid argument") {
			return nil, status.Error(codes.InvalidArgument, e.Error())
		}
		return nil, status.Error(codes.Internal, e.Error())
	}
	ns.mounts[req.VolumeId] = &mountPoint{IdentityFile: privateKeyPath, MountPath: targetPath, VolumeId: req.VolumeId}
	return &csi.NodePublishVolumeResponse{}, nil
}

func (ns *nodeServer) NodeUnpublishVolume(ctx context.Context, req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {
	targetPath := req.GetTargetPath()
	notMnt, err := mount.New("").IsLikelyNotMountPoint(targetPath)

	if err != nil {
		if os.IsNotExist(err) {
			return nil, status.Error(codes.NotFound, "Targetpath not found")
		} else {
			return nil, status.Error(codes.Internal, err.Error())
		}
	}
	if notMnt {
		return nil, status.Error(codes.NotFound, "Volume not mounted")
	}

	err = util.UnmountPath(req.GetTargetPath(), mount.New(""))
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if point, ok := ns.mounts[req.VolumeId]; ok {
		err := os.Remove(point.IdentityFile)
		if err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
		delete(ns.mounts, point.VolumeId)
		glog.Infof("successfully unmount volume: %s", point)
	}

	return &csi.NodeUnpublishVolumeResponse{}, nil
}

func (ns *nodeServer) NodeUnstageVolume(ctx context.Context, req *csi.NodeUnstageVolumeRequest) (*csi.NodeUnstageVolumeResponse, error) {
	return &csi.NodeUnstageVolumeResponse{}, nil
}

func (ns *nodeServer) NodeStageVolume(ctx context.Context, req *csi.NodeStageVolumeRequest) (*csi.NodeStageVolumeResponse, error) {
	return &csi.NodeStageVolumeResponse{}, nil
}

func validateVolumeContext(req *csi.NodePublishVolumeRequest) error {
	if _, ok := req.GetVolumeContext()["server"]; !ok {
		return status.Errorf(codes.InvalidArgument, "missing volume context value: server")
	}
	if _, ok := req.GetVolumeContext()["user"]; !ok {
		return status.Errorf(codes.InvalidArgument, "missing volume context value: user")
	}
	if _, ok := req.GetVolumeContext()["share"]; !ok {
		return status.Errorf(codes.InvalidArgument, "missing volume context value: share")
	}

	_, pkOk := req.GetVolumeContext()["privateKey"]
	_, pwOk := req.GetVolumeContext()["password"]
	if !(pkOk || pwOk) {
		return status.Errorf(codes.InvalidArgument, "missing volume context value: privateKey or password")
	}
	return nil
}

func getPublicKeySecret(secretName string) (*v1.Secret, error) {
	namespaceAndSecret := strings.SplitN(secretName, "/", 2)
	namespace := namespaceAndSecret[0]
	name := namespaceAndSecret[1]

	clientset, e := GetK8sClient()
	if e != nil {
		return nil, status.Errorf(codes.Internal, "can not create kubernetes client: %s", e)
	}

	secret, e := clientset.CoreV1().
		Secrets(namespace).
		Get(name, metav1.GetOptions{})

	if e != nil {
		return nil, status.Errorf(codes.Internal, "can not get secret %s: %s", secretName, e)
	}

	if secret.Type != v1.SecretTypeSSHAuth {
		return nil, status.Errorf(codes.InvalidArgument, "type of secret %s is not %s", secretName, v1.SecretTypeSSHAuth)
	}
	return secret, nil
}

func writePrivateKey(secret *v1.Secret) (string, error) {
	f, e := ioutil.TempFile("", "pk-*")
	defer f.Close()
	if e != nil {
		return "", status.Errorf(codes.Internal, "can not create tmp file for pk: %s", e)
	}

	_, e = f.Write(secret.Data[v1.SSHAuthPrivateKey])
	if e != nil {
		return "", status.Errorf(codes.Internal, "can not create tmp file for pk: %s", e)
	}
	e = f.Chmod(0600)
	if e != nil {
		return "", status.Errorf(codes.Internal, "can not change rights for pk: %s", e)
	}
	return f.Name(), nil
}

func parseRawOpts(result map[string]string, sshOpts string) {
	if sshOpts == "" {
		return
	}

	splitOpts := strings.Split(sshOpts, ";")
	for _, item := range splitOpts {
		parts := strings.SplitN(item, "=", 2)
		switch len(parts) {
		case 0:
			continue
		case 1:
			result[parts[0]] = ""
		case 2:
			result[parts[0]] = parts[1]
		}
	}
}

func Mount(user, host, port, dir, target, password, privateKey, sshOpts string) error {
	mountCmd := "sshfs"
	mountArgs := generateMountArgs(user, host, port, dir, target, password, privateKey, sshOpts)

	// create target, os.Mkdirall is noop if it exists
	err := os.MkdirAll(target, 0750)
	if err != nil {
		return err
	}

	glog.Infof("executing mount command cmd=%s, args=%s", mountCmd, mountArgs)

	cmd := exec.Command(mountCmd, mountArgs...)

	if password != "" {
		if err = pipePasswordIn(cmd, password); err != nil {
			glog.Errorf("failed to get std in from sshfs: %v", err)
			return err
		}
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mounting failed: %v cmd: '%s %s' output: %q",
			err, mountCmd, strings.Join(mountArgs, " "), string(out))
	}

	return nil
}

func generateMountArgs(user, host, port, dir, target, password, privateKey, sshOpts string) []string {

	optsMap := map[string]string{
		"StrictHostKeyChecking": "accept-new",
		"UserKnownHostsFile":    "/dev/null",
		"allow_other":           "",
		"uid":                   "100",
		"gid":                   "0",
		"reconnect":             "",
		"ServerAliveInterval":   "15",
		"ServerAliveCountMax":   "3",
		"port":                  port,
	}

	if privateKey != "" {
		optsMap["IdentityFile"] = privateKey
	}

	if password != "" {
		optsMap["password_stdin"] = ""
	}

	parseRawOpts(optsMap, sshOpts)

	source := fmt.Sprintf("%s@%s:%s", user, host, dir)
	mountArgs := []string{source, target}

	// just to simplify testing
	sortedKeys := getSortedKeys(optsMap)
	for _, key := range sortedKeys {
		val := optsMap[key]
		var opt string
		if val != "" {
			opt = fmt.Sprintf("%s=%s", key, val)
		} else {
			opt = key
		}
		mountArgs = append(mountArgs, "-o", opt)
	}
	return mountArgs
}

func getSortedKeys(optsMap map[string]string) []string {
	var keys []string
	for key := range optsMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func pipePasswordIn(cmd *exec.Cmd, password string) error {
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	defer stdin.Close()

	count, err := io.WriteString(stdin, password)
	if err != nil {
		return err
	}

	glog.Infof("wrote %d password bytes", count)

	return nil
}
