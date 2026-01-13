package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/richardmsong/aqua-scan-triggerer/api/v1alpha1"
)

var _ = Describe("PodGateReconciler", func() {
	var (
		scheme *runtime.Scheme
		ctx    context.Context
	)

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		Expect(corev1.AddToScheme(scheme)).To(Succeed())
		Expect(securityv1alpha1.AddToScheme(scheme)).To(Succeed())
		ctx = context.Background()
	})

	Describe("Reconcile", func() {
		Context("when all images are registered", func() {
			It("should remove the scheduling gate", func() {
				// Create a pod with our gate
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-pod",
						Namespace: "default",
					},
					Spec: corev1.PodSpec{
						SchedulingGates: []corev1.PodSchedulingGate{
							{Name: SchedulingGateName},
						},
						Containers: []corev1.Container{
							{Name: "app", Image: "nginx:latest"},
						},
					},
				}

				// Create a registered ImageScan
				imageScan := &securityv1alpha1.ImageScan{
					ObjectMeta: metav1.ObjectMeta{
						Name:      imageScanName(imageRef{image: "nginx:latest"}),
						Namespace: "default",
					},
					Spec: securityv1alpha1.ImageScanSpec{
						Image: "nginx:latest",
					},
					Status: securityv1alpha1.ImageScanStatus{
						Phase: securityv1alpha1.ScanPhaseRegistered,
					},
				}

				client := fake.NewClientBuilder().
					WithScheme(scheme).
					WithObjects(pod, imageScan).
					Build()

				r := &PodGateReconciler{
					Client: client,
					Scheme: scheme,
				}

				_, err := r.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "test-pod",
						Namespace: "default",
					},
				})
				Expect(err).NotTo(HaveOccurred())

				// Verify gate was removed
				var updatedPod corev1.Pod
				err = client.Get(ctx, types.NamespacedName{
					Name: "test-pod", Namespace: "default",
				}, &updatedPod)
				Expect(err).NotTo(HaveOccurred())
				Expect(hasSchedulingGate(&updatedPod, SchedulingGateName)).To(BeFalse())
			})
		})
	})
})
