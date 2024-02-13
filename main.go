package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/strslice"
	dockerclient "github.com/docker/docker/client"
	"github.com/fatih/color"
	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/sethvargo/go-envconfig"
	flag "github.com/spf13/pflag"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/wait"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/rest"
	"k8s.io/utils/strings/slices"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/kustomize/kyaml/resid"
)

type Config struct {
	Log struct {
		Level    string `env:"LOG_LEVEL, default=fatal"`
		Encoding string `env:"LOG_ENCODING, default=json"`
	}
	File              string `env:"FILE, default=/dev/stdin"`
	FailFast          bool   `env:"FAIL_FAST"`
	AllowFailure      bool   `env:"ALLOW_FAILURE"`
	SkipAutoNamespace bool   `env:"SKIP_AUTO_NAMESPACE"`
	Namespace         string `env:"NAMESPACE"`
	Table             bool   `env:"TABLE"`
	ExcludeValid      bool   `env:"EXCLUDE_VALID"`
	KubeVersion       string `env:"KUBE_VERSION, default=1.28.0"`
	EtcdVersion       string `env:"ETCD_VERSION, default=3.5.11"`
	ApiServerRegistry string `env:"API_SERVER_REGISTRY, default=registry.k8s.io/kube-apiserver"`
	EtcdRegistry      string `env:"ETCD_REGISTRY, default=quay.io/coreos/etcd"`
	ApiServerFlags    string `env:"API_SERVER_FLAGS, default=--disable-admission-plugins=MutatingAdmissionWebhook,ValidatingAdmissionPolicy,ValidatingAdmissionWebhook"`
}

var (
	config = &Config{}
	tbl    table.Writer
	output = os.Stdout
)

func init() {
	flag.StringVarP(&config.Log.Level, "log-level", "l", "", "Define the log level (default is warning) [debug,info,warn,error]")
	flag.StringVarP(&config.Log.Encoding, "log-encoding", "e", "", "Define the log format (default is json) [json,console]")
	flag.StringVarP(&config.File, "file", "f", "", "Path to input")
	flag.BoolVarP(&config.SkipAutoNamespace, "skip-auto-namespace", "", false, "Do not create a namespace if it does not exists yet while validating a resource")
	flag.BoolVar(&config.AllowFailure, "allow-failure", false, "Do not exit > 0 if an error occured")
	flag.BoolVar(&config.Table, "table", false, "Output as table")
	flag.BoolVar(&config.ExcludeValid, "exclude-valid", false, "Only included invalid manifests in the output")
	flag.StringVarP(&config.Namespace, "namespace", "", "", "Default namespace to apply to resources without a namespace")
	flag.BoolVar(&config.FailFast, "fail-fast", false, "Exit early if an error occured")
	flag.StringVarP(&config.KubeVersion, "kube-version", "", "", "Kubernetes version, for instead 1.27.0. If not set the latest stable one is used")
	flag.StringVarP(&config.ApiServerRegistry, "api-server-registry", "", "", "OCI registry for pulling the kube-apiserver image")
	flag.StringVarP(&config.EtcdRegistry, "etcd-registry", "", "", "OCI registry for pulling the etcd image")
	flag.StringVarP(&config.EtcdVersion, "etcd-version", "", "", "The version for etcd")
	flag.StringVarP(&config.ApiServerFlags, "api-server-flags", "", "", "Set additional kube-apiserver flags")

	tbl = table.NewWriter()
	tbl.SetOutputMirror(output)
	tbl.AppendHeader(table.Row{"Name", " Namespace", "Kind", "GV", "Result", "Message"})
}

func main() {
	ctx := context.TODO()
	err := envconfig.Process(ctx, config)
	must(err)

	flag.Parse()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	logger, err := buildLogger()
	must(err)
	log.SetLogger(logger)

	dockerClient, err := dockerclient.NewClientWithOpts(
		dockerclient.FromEnv,
	)
	must(err)
	dockerClient.NegotiateAPIVersion(ctx)

	g := new(errgroup.Group)
	g.Go(func() error {
		tag, _ := strings.CutPrefix(config.EtcdVersion, "v")
		return pullImage(ctx, dockerClient, logger, fmt.Sprintf("%s:v%s", config.EtcdRegistry, tag))
	})
	g.Go(func() error {
		tag, _ := strings.CutPrefix(config.KubeVersion, "v")
		return pullImage(ctx, dockerClient, logger, fmt.Sprintf("%s:v%s", config.ApiServerRegistry, tag))
	})

	must(g.Wait())

	logger.V(1).Info("starting etcd")
	etcdSpecs, err := startEtcd(ctx, dockerClient)
	must(err)

	authToken := make([]byte, 24)
	_, err = rand.Read(authToken)
	must(err)

	logger.V(1).Info("starting kube-apiserver")
	apiSrvSpecs, err := startAPIServer(ctx, dockerClient, etcdSpecs, authToken)
	must(err)

	kConfig := rest.Config{
		Host:        fmt.Sprintf("%s:6443", apiSrvSpecs.NetworkSettings.DefaultNetworkSettings.IPAddress),
		BearerToken: fmt.Sprintf("%X", authToken),
		TLSClientConfig: rest.TLSClientConfig{
			Insecure: true,
		},
	}

	f, err := os.Open(config.File)
	must(err)

	kubeClient, err := client.New(&kConfig, client.Options{})
	must(err)

	cleanup := func() {
		_ = resetContainer(context.TODO(), dockerClient, "/yakmv-etcd")
		_ = resetContainer(context.TODO(), dockerClient, "/yakmv-api-server")
	}

	defer cleanup()
	go func() {
		logger.Info("received os signal", "signal", <-signals)
		cleanup()
		os.Exit(1)
	}()

	err = wait.ExponentialBackoff(wait.Backoff{
		Duration: time.Millisecond * 50,
		Jitter:   0.1,
		Steps:    10,
		Factor:   2,
	}, func() (bool, error) {
		logger.V(1).Info("waiting for kube-apiserver")
		return kubeClient.List(ctx, &corev1.NamespaceList{}) == nil, nil
	})
	must(err)

	scheme := kubeClient.Scheme()
	apiextv1.AddToScheme(scheme)
	factory := serializer.NewCodecFactory(scheme)
	decoder := factory.UniversalDeserializer()

	var objects []client.Object
	namespaces := make(indexedObjects)
	var crds []client.Object
	multidocReader := utilyaml.NewYAMLReader(bufio.NewReader(f))

	for {
		resourceYAML, err := multidocReader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}

			must(err)
		}
		obj := unstructured.Unstructured{}
		_, gvk, err := decoder.Decode(
			resourceYAML,
			nil,
			&obj)

		if err != nil && !kruntime.IsMissingKind(err) {
			continue
		} else if kruntime.IsMissingKind(err) {
			continue
		}

		if obj.GetNamespace() == "" {
			obj.SetNamespace(config.Namespace)
		}

		if _, ok := namespaces[obj.GetNamespace()]; !config.SkipAutoNamespace && obj.GetNamespace() != "" && !ok {
			namespaces[obj.GetNamespace()] = &corev1.Namespace{ObjectMeta: v1.ObjectMeta{Name: obj.GetNamespace()}}
		}

		switch *gvk {
		case schema.GroupVersionKind{Group: apiextv1.SchemeGroupVersion.Group, Version: apiextv1.SchemeGroupVersion.Version, Kind: "CustomResourceDefinition"}:
			crd := apiextv1.CustomResourceDefinition{}
			_, _, err = decoder.Decode(
				resourceYAML,
				&schema.GroupVersionKind{Group: apiextv1.SchemeGroupVersion.Group, Version: apiextv1.SchemeGroupVersion.Version, Kind: "CustomResourceDefinition"},
				&crd)

			if err != nil {
				must(err)
			}

			// Conversion Webhook is unsupported since there will be no pods running handling the conversion request
			if crd.Spec.Conversion != nil {
				crd.Spec.Conversion.Strategy = "None"
				crd.Spec.Conversion.Webhook = nil
			}

			crds = append(crds, &crd)
		case schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Namespace"}:
			namespaces[obj.GetName()] = &obj
		default:
			objects = append(objects, &obj)
		}
	}

	sort.Slice(objects, func(i, j int) bool {
		iGvk := resid.NewGvk(objects[i].GetObjectKind().GroupVersionKind().Group, objects[i].GetObjectKind().GroupVersionKind().Version, objects[i].GetObjectKind().GroupVersionKind().Kind)
		jGvk := resid.NewGvk(objects[j].GetObjectKind().GroupVersionKind().Group, objects[j].GetObjectKind().GroupVersionKind().Version, objects[j].GetObjectKind().GroupVersionKind().Kind)
		return iGvk.IsLessThan(jGvk)
	})

	sum, err := validate(ctx, kubeClient, logger, crds, namespaces.Slice(), objects)
	must(err)

	if config.Table && tbl.Length() > 0 {
		tbl.Render()
	}

	fmt.Fprintln(output, sum.String())

	if !config.AllowFailure && sum.errors > 0 {
		os.Exit(1)
	}
}

func validate(ctx context.Context, kubeClient client.Client, logger logr.Logger, objects ...[]client.Object) (summary, error) {
	results := make(chan error)
	total := summary{}

	for _, obj := range objects {
		if len(obj) == 0 {
			continue
		}

		applyObjects(ctx, kubeClient, logger, obj, results)
		sum, err := await(ctx, len(obj), results)
		must(err)

		total.Add(sum)
	}

	return total, nil
}

func await(ctx context.Context, abort int, results chan error) (summary, error) {
	sum := summary{}

	for {
		select {
		case <-ctx.Done():
			return sum, nil
		case err := <-results:
			sum.total++
			if err != nil {
				sum.errors++
			}

			if err != nil && config.FailFast {
				return sum, err
			}

			if sum.total == abort {
				return sum, nil
			}
			break
		}
	}

}

type summary struct {
	total  int
	errors int
}

func (s *summary) Add(sum summary) {
	s.total += sum.total
	s.errors += sum.errors
}

func (s *summary) String() string {
	return fmt.Sprintf("total: %d, Invalid: %d", s.total, s.errors)
}

type indexedObjects map[string]client.Object

func (i indexedObjects) Slice() []client.Object {
	var objects []client.Object
	for _, obj := range i {
		objects = append(objects, obj)
	}

	return objects
}

func applyObjects(ctx context.Context, kubeClient client.Client, logger logr.Logger, objects []client.Object, results chan error) {
	for _, o := range objects {
		obj := o
		go func(obj client.Object) {
			gvk := obj.GetObjectKind().GroupVersionKind()
			err := kubeClient.Create(ctx, obj)
			logger := logger.WithValues(
				"name", obj.GetName(),
				"namespace", obj.GetNamespace(),
				"kind", gvk.Kind,
				"group", gvk.Group,
				"version", gvk.Version,
			)

			if err != nil {
				if kerrors.IsAlreadyExists(err) {
					return
				}

				logger.Error(err, "failed to create resource")

				if config.Table {
					tbl.AppendRow([]interface{}{obj.GetName(), obj.GetNamespace(), gvk.Kind, strings.TrimLeft(fmt.Sprintf("%s/%s", gvk.Group, gvk.Version), "/"), color.RedString("FAIL"), err.Error()})
				}
			} else if !config.ExcludeValid {
				logger.V(1).Info("resource created", "name", obj.GetName())

				if config.Table {
					tbl.AppendRow([]interface{}{obj.GetName(), obj.GetNamespace(), gvk.Kind, strings.TrimLeft(fmt.Sprintf("%s/%s", gvk.Group, gvk.Version), "/"), color.GreenString("VALID"), ""})
				}
			}

			results <- err
		}(obj)
	}
}

func buildLogger() (logr.Logger, error) {
	logOpts := zap.NewDevelopmentConfig()
	logOpts.Encoding = config.Log.Encoding

	err := logOpts.Level.UnmarshalText([]byte(config.Log.Level))
	if err != nil {
		return logr.Discard(), err
	}

	zapLog, err := logOpts.Build()
	if err != nil {
		return logr.Discard(), err
	}

	return zapr.NewLogger(zapLog), nil
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func getContainerIDByName(ctx context.Context, dockerClient *dockerclient.Client, name string) (string, error) {
	containers, err := dockerClient.ContainerList(ctx, types.ContainerListOptions{
		All: true,
	})

	if err != nil {
		return "", err
	}

	for _, container := range containers {
		if slices.Contains(container.Names, name) {
			return container.ID, nil
		}
	}

	return "", errors.New("no such container found")
}

func resetContainer(ctx context.Context, dockerClient *dockerclient.Client, id string) error {
	id, err := getContainerIDByName(ctx, dockerClient, id)

	if err == nil {
		_ = dockerClient.ContainerStop(ctx, id, container.StopOptions{})
		err = dockerClient.ContainerRemove(ctx, id, types.ContainerRemoveOptions{})
		if err != nil {
			return err
		}
	}

	return nil
}

func pullImage(ctx context.Context, dockerClient *dockerclient.Client, logger logr.Logger, image string) error {
	images, err := dockerClient.ImageList(ctx, types.ImageListOptions{})
	if err != nil {
		return err
	}

	for _, img := range images {
		if slices.Contains(img.RepoTags, image) {
			logger.V(1).Info("image already exists", "tag", image)
			return nil
		}
	}

	logger.Info("pulling image", "tag", image)
	w, err := dockerClient.ImagePull(ctx, image, types.ImagePullOptions{})
	if err != nil {
		return err
	}

	defer w.Close()
	_, err = io.Copy(io.Discard, w)
	return err
}

func startEtcd(ctx context.Context, dockerClient *dockerclient.Client) (types.ContainerJSON, error) {
	tag, _ := strings.CutPrefix(config.EtcdVersion, "v")
	err := resetContainer(ctx, dockerClient, "/yakmv-etcd")
	if err != nil {
		return types.ContainerJSON{}, err
	}

	cont, err := dockerClient.ContainerCreate(
		ctx,
		&container.Config{
			Image: fmt.Sprintf("%s:v%s", config.EtcdRegistry, tag),
			Cmd: strslice.StrSlice{
				"/usr/local/bin/etcd",
				"--advertise-client-urls=http://0.0.0.0:2379",
				"--listen-client-urls=http://0.0.0.0:2379",
				"--initial-advertise-peer-urls=http://0.0.0.0:2380",
				"--listen-peer-urls=http://0.0.0.0:2380",
				`--initial-cluster=default=http://0.0.0.0:2380`,
			},
		},
		&container.HostConfig{}, nil, nil, "yakmv-etcd")

	if err != nil {
		return types.ContainerJSON{}, err
	}

	err = dockerClient.ContainerStart(ctx, cont.ID, types.ContainerStartOptions{})
	if err != nil {
		return types.ContainerJSON{}, err
	}

	specs, err := dockerClient.ContainerInspect(ctx, cont.ID)
	if err != nil {
		return types.ContainerJSON{}, err
	}

	return specs, nil
}

func startAPIServer(ctx context.Context, dockerClient *dockerclient.Client, etcd types.ContainerJSON, token []byte) (types.ContainerJSON, error) {
	err := resetContainer(ctx, dockerClient, "/yakmv-kube-apiserver")
	if err != nil {
		return types.ContainerJSON{}, err
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return types.ContainerJSON{}, err
	}

	certDir, err := os.MkdirTemp("", "cert")
	if err != nil {
		return types.ContainerJSON{}, err
	}

	cert, err := os.Create(filepath.Join(certDir, "service-account-key.pem"))
	if err != nil {
		return types.ContainerJSON{}, err
	}

	err = pem.Encode(cert, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})
	if err != nil {
		return types.ContainerJSON{}, err
	}

	tokenFile := fmt.Sprintf("%X,default,default", token)
	err = os.WriteFile(filepath.Join(certDir, "token"), []byte(tokenFile), 0644)
	if err != nil {
		return types.ContainerJSON{}, err
	}

	cmd := append(strslice.StrSlice{
		"/usr/local/bin/kube-apiserver",
		fmt.Sprintf("--etcd-servers=%s:2379", etcd.NetworkSettings.DefaultNetworkSettings.IPAddress),
		"--anonymous-auth",
		"--service-account-issuer=https://validation",
		"--service-account-key-file=/certs/service-account-key.pem",
		"--service-account-signing-key-file=/certs/service-account-key.pem",
		"--token-auth-file=/certs/token",
		"--enable-priority-and-fairness=false",
	}, strings.Split(config.ApiServerFlags, " ")...)

	tag, _ := strings.CutPrefix(config.KubeVersion, "v")
	cont, err := dockerClient.ContainerCreate(
		ctx,
		&container.Config{
			Image: fmt.Sprintf("%s:v%s", config.ApiServerRegistry, tag),
			Cmd:   cmd,
		},
		&container.HostConfig{
			Mounts: []mount.Mount{
				{
					Type:   mount.TypeBind,
					Source: certDir,
					Target: "/certs",
				},
			},
		},
		nil,
		nil,
		"yakmv-kube-apiserver")

	if err != nil {
		return types.ContainerJSON{}, err
	}

	err = dockerClient.ContainerStart(ctx, cont.ID, types.ContainerStartOptions{})
	if err != nil {
		return types.ContainerJSON{}, err
	}

	specs, err := dockerClient.ContainerInspect(ctx, cont.ID)
	if err != nil {
		return types.ContainerJSON{}, err
	}

	return specs, nil
}
