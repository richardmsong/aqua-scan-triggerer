package main

import (
	"flag"
	"os"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	securityv1alpha1 "github.com/richardmsong/aqua-scan-triggerer/api/v1alpha1"
	"github.com/richardmsong/aqua-scan-triggerer/internal/controller"
	webhookpkg "github.com/richardmsong/aqua-scan-triggerer/internal/webhook"
	"github.com/richardmsong/aqua-scan-triggerer/pkg/aqua"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(securityv1alpha1.AddToScheme(scheme))
}

func main() {
	var (
		metricsAddr          string
		probeAddr            string
		enableLeaderElection bool
		aquaURL              string
		aquaAPIKey           string
		aquaUsername         string
		aquaPassword         string
		aquaHMACSecret       string
		aquaAuthMode         string
		excludedNamespaces   string
		scanNamespace        string
		rescanInterval       time.Duration
	)

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false, "Enable leader election.")
	flag.StringVar(&aquaURL, "aqua-url", os.Getenv("AQUA_URL"), "Aqua server URL")
	flag.StringVar(&aquaAPIKey, "aqua-api-key", os.Getenv("AQUA_API_KEY"), "Aqua API key (for token auth mode)")
	flag.StringVar(&aquaUsername, "aqua-username", os.Getenv("AQUA_USERNAME"), "Aqua username (for credentials auth mode)")
	flag.StringVar(&aquaPassword, "aqua-password", os.Getenv("AQUA_PASSWORD"), "Aqua password (for credentials auth mode)")
	flag.StringVar(&aquaHMACSecret, "aqua-hmac-secret", os.Getenv("AQUA_HMAC_SECRET"), "HMAC secret for request signing (optional)")
	flag.StringVar(&aquaAuthMode, "aqua-auth-mode", os.Getenv("AQUA_AUTH_MODE"), "Authentication mode: 'token' or 'credentials' (default: auto-detect)")
	flag.StringVar(&excludedNamespaces, "excluded-namespaces", "kube-system,kube-public,cert-manager", "Comma-separated namespaces to exclude")
	flag.StringVar(&scanNamespace, "scan-namespace", "", "Namespace for ImageScan CRs (empty = same as pod)")
	flag.DurationVar(&rescanInterval, "rescan-interval", 24*time.Hour, "Interval for rescanning images")

	opts := zap.Options{Development: true}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// Parse excluded namespaces
	excludedNS := make(map[string]bool)
	for _, ns := range strings.Split(excludedNamespaces, ",") {
		ns = strings.TrimSpace(ns)
		if ns != "" {
			excludedNS[ns] = true
		}
	}

	// Determine auth mode and create auth config
	authConfig := buildAuthConfig(aquaAuthMode, aquaAPIKey, aquaUsername, aquaPassword, aquaHMACSecret)

	// Create Aqua client
	aquaClient := aqua.NewClient(aqua.Config{
		BaseURL: aquaURL,
		Auth:    authConfig,
		Timeout: 30 * time.Second,
	})

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "aqua-scan-gate.security.example.com",
		HealthProbeBindAddress: probeAddr,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Setup ImageScan controller
	if err = (&controller.ImageScanReconciler{
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		AquaClient:     aquaClient,
		RescanInterval: rescanInterval,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ImageScan")
		os.Exit(1)
	}

	// Setup Pod gate controller
	if err = (&controller.PodGateReconciler{
		Client:             mgr.GetClient(),
		Scheme:             mgr.GetScheme(),
		Recorder:           mgr.GetEventRecorderFor("aqua-scan-gate"),
		ScanNamespace:      scanNamespace,
		ExcludedNamespaces: excludedNS,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PodGate")
		os.Exit(1)
	}

	// Setup webhook
	mgr.GetWebhookServer().Register("/mutate-v1-pod", &webhook.Admission{
		Handler: &webhookpkg.PodMutator{
			Client:             mgr.GetClient(),
			ExcludedNamespaces: excludedNS,
		},
	})

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

// buildAuthConfig creates an AuthConfig based on provided parameters
// It auto-detects the auth mode if not explicitly specified
func buildAuthConfig(mode, apiKey, username, password, hmacSecret string) aqua.AuthConfig {
	authConfig := aqua.AuthConfig{
		HMACSecret: hmacSecret,
	}

	// Determine auth mode
	switch mode {
	case "token":
		authConfig.Mode = aqua.AuthModeToken
		authConfig.Token = apiKey
	case "credentials":
		authConfig.Mode = aqua.AuthModeCredentials
		authConfig.Username = username
		authConfig.Password = password
	default:
		// Auto-detect based on what's provided
		if username != "" && password != "" {
			authConfig.Mode = aqua.AuthModeCredentials
			authConfig.Username = username
			authConfig.Password = password
		} else if apiKey != "" {
			authConfig.Mode = aqua.AuthModeToken
			authConfig.Token = apiKey
		}
	}

	return authConfig
}
