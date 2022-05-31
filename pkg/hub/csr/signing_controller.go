package csr

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	capi "k8s.io/api/certificates/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	certificatesinformers "k8s.io/client-go/informers/certificates/v1"
	"k8s.io/client-go/kubernetes"
	certificateslisters "k8s.io/client-go/listers/certificates/v1"
	"k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/certificate/csr"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/klog/v2"
)

// csrSigningController sign approved CertificateSigningRequests for an accepted spoke cluster on the hub.
type csrSigningController struct {
	certFile      string
	keyFile       string
	certTTL       time.Duration
	ca            *CertificateAuthority
	kubeClient    kubernetes.Interface
	csrLister     certificateslisters.CertificateSigningRequestLister
	eventRecorder events.Recorder
}

// NewCSRApprovingController creates a new csr approving controller
func NewCSRSigningController(kubeClient kubernetes.Interface, csrInformer certificatesinformers.CertificateSigningRequestInformer, recorder events.Recorder) factory.Controller {
	c := &csrSigningController{
		certFile:      "/ca/ca.crt",
		keyFile:       "/ca/ca.key",
		certTTL:       30 * 24 * time.Hour,
		kubeClient:    kubeClient,
		csrLister:     csrInformer.Lister(),
		eventRecorder: recorder.WithComponentSuffix("csr-signing-controller"),
	}
	return factory.New().
		WithInformersQueueKeyFunc(func(obj runtime.Object) string {
			accessor, _ := meta.Accessor(obj)
			return accessor.GetName()
		}, csrInformer.Informer()).
		WithSync(c.sync).
		ToController("CSRSigningController", recorder)
}

func (c *csrSigningController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	csrName := syncCtx.QueueKey()
	klog.Infof("Reconciling CertificateSigningRequests %q", csrName)
	csr, err := c.csrLister.Get(csrName)
	if errors.IsNotFound(err) {
		klog.Infof("CertificateSigningRequests %q not found", csrName)
		return nil
	}
	if err != nil {
		return err
	}

	// csr is not generated for cluster/add-on registration/renewal, do nothing.
	if _, ok := csr.Labels[spokeClusterNameLabel]; !ok {
		klog.Infof("CertificateSigningRequests %q has no cluster label", csrName)
		return nil
	}

	// csr is not approved, do nothing.
	if !isApproved(csr) {
		klog.Infof("CertificateSigningRequests %q has not been approved", csrName)
		return nil
	}

	// csr is signed, do nothing.
	if len(csr.Status.Certificate) > 0 {
		klog.Infof("CertificateSigningRequests %q has already been signed", csrName)
		return nil
	}

	// the signer of csr is not KubeAPIServerClientSigner, do nothing
	if csr.Spec.SignerName != certificatesv1.KubeAPIServerClientSignerName {
		klog.Infof("CertificateSigningRequests %q has unknown signer %s", csrName, csr.Spec.SignerName)
		return nil
	}

	if err = validAPIServerClientUsages(csr.Spec.Usages); err != nil {
		csr.Status.Conditions = append(csr.Status.Conditions, capi.CertificateSigningRequestCondition{
			Type:           capi.CertificateFailed,
			Status:         v1.ConditionTrue,
			Reason:         "SignerValidationFailure",
			Message:        err.Error(),
			LastUpdateTime: metav1.Now(),
		})
		_, err = c.kubeClient.CertificatesV1().CertificateSigningRequests().UpdateStatus(context.TODO(), csr, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("error adding failure condition for csr: %v", err)
		}
		klog.Infof("CertificateSigningRequests %q has invalid usages: %v", csrName, err)
		return nil
	}

	if err = c.initCA(); err != nil {
		return err
	}

	x509cr, err := parseCSR(csr.Spec.Request)
	if err != nil {
		return fmt.Errorf("unable to parse csr %q: %v", csr.Name, err)
	}

	cert, err := c.sign(x509cr, csr.Spec.Usages, csr.Spec.ExpirationSeconds, nil)
	if err != nil {
		return fmt.Errorf("error auto signing csr: %v", err)
	}
	csr = csr.DeepCopy()
	csr.Status.Certificate = cert
	_, err = c.kubeClient.CertificatesV1().CertificateSigningRequests().UpdateStatus(context.TODO(), csr, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating signature for csr: %v", err)
	}

	c.eventRecorder.Eventf("ManagedClusterCSRSigned", "csr %q is signed by csr signer", csr.Name)
	return nil
}

func (c *csrSigningController) initCA() error {
	if c.ca != nil {
		return nil
	}

	certPEM, keyPEM, err := loadCertKeyPair(c.certFile, c.keyFile)
	if err != nil {
		return err
	}

	certs, err := cert.ParseCertsPEM(certPEM)
	if err != nil {
		return fmt.Errorf("error reading CA cert file %q: %v", c.certFile, err)
	}
	if len(certs) != 1 {
		return fmt.Errorf("error reading CA cert file %q: expected 1 certificate, found %d", c.certFile, len(certs))
	}

	key, err := keyutil.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return fmt.Errorf("error reading CA key file %q: %v", c.keyFile, err)
	}
	priv, ok := key.(crypto.Signer)
	if !ok {
		return fmt.Errorf("error reading CA key file %q: key did not implement crypto.Signer", c.keyFile)
	}

	c.ca = &CertificateAuthority{
		RawCert: certPEM,
		RawKey:  keyPEM,

		Certificate: certs[0],
		PrivateKey:  priv,
	}
	return nil
}

func (c *csrSigningController) sign(x509cr *x509.CertificateRequest, usages []capi.KeyUsage, expirationSeconds *int32, now func() time.Time) ([]byte, error) {
	der, err := c.ca.Sign(x509cr.Raw, PermissiveSigningPolicy{
		TTL:      c.duration(expirationSeconds),
		Usages:   usages,
		Backdate: 5 * time.Minute, // this must always be less than the minimum TTL requested by a user (see sanity check requestedDuration below)
		Short:    8 * time.Hour,   // 5 minutes of backdating is roughly 1% of 8 hours
		Now:      now,
	})
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func (c *csrSigningController) duration(expirationSeconds *int32) time.Duration {
	if expirationSeconds == nil {
		return c.certTTL
	}

	// honor requested duration is if it is less than the default TTL
	// use 10 min (2x hard coded backdate above) as a sanity check lower bound
	const min = 10 * time.Minute
	switch requestedDuration := csr.ExpirationSecondsToDuration(*expirationSeconds); {
	case requestedDuration > c.certTTL:
		return c.certTTL

	case requestedDuration < min:
		return min

	default:
		return requestedDuration
	}
}

// ParseCSR extracts the CSR from the bytes and decodes it.
func parseCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("PEM block type must be CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	return csr, nil
}

func isApproved(csr *certificatesv1.CertificateSigningRequest) bool {
	approved := false
	for _, condition := range csr.Status.Conditions {
		if condition.Type == certificatesv1.CertificateDenied {
			return false
		} else if condition.Type == certificatesv1.CertificateApproved {
			approved = true
		}
	}
	return approved
}

func loadCertKeyPair(certFile, keyFile string) ([]byte, []byte, error) {
	cert, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, nil, err
	}
	key, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, nil, err
	}
	if len(cert) == 0 {
		return nil, nil, fmt.Errorf("missing content for cert %q", certFile)
	}
	if len(cert) == 0 || len(key) == 0 {
		return nil, nil, fmt.Errorf("missing content for key %q", keyFile)
	}

	// Ensure that the key matches the cert and both are valid
	_, err = tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

func validAPIServerClientUsages(usages []capi.KeyUsage) error {
	hasClientAuth := false
	for _, u := range usages {
		switch u {
		// these usages are optional
		case capi.UsageDigitalSignature, capi.UsageKeyEncipherment:
		case capi.UsageClientAuth:
			hasClientAuth = true
		default:
			return fmt.Errorf("invalid usage for client certificate: %s", u)
		}
	}
	if !hasClientAuth {
		return fmt.Errorf("missing required usage for client certificate: %s", capi.UsageClientAuth)
	}
	return nil
}
