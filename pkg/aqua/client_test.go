package aqua

import (
	"context"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ConvertImageRef", func() {
	var (
		ctx    context.Context
		client *aquaClient
	)

	BeforeEach(func() {
		ctx = context.Background()
		// Create a real aquaClient with a pre-populated registry cache
		// This avoids the need for actual API calls during tests
		client = &aquaClient{
			config: Config{
				APIKey:    "test-key",
				APISecret: "test-secret",
				Region:    "us",
			},
			registryCache: map[string]string{
				"docker.io":                                    "Docker Hub",
				"gcr.io":                                       "GCR",
				"eu.gcr.io":                                    "GCR EU",
				"123456789012.dkr.ecr.us-east-1.amazonaws.com": "AWS ECR",
				"myregistry.azurecr.io":                        "Azure ACR",
				"quay.io":                                      "Quay",
				"registry.io":                                  "Custom Registry",
				"registry.io:5000":                             "Custom Registry",
				"my-registry.io":                               "My Registry",
			},
			registryCacheMu:      sync.RWMutex{},
			registryCacheRefresh: time.Now(),
		}
	})

	Describe("Docker Hub images", func() {
		It("should parse image with namespace and tag", func() {
			registry, image, tag, err := client.ConvertImageRef(ctx, "docker.io/library/python:3.12.12")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Docker Hub"))
			Expect(image).To(Equal("library/python"))
			Expect(tag).To(Equal("3.12.12"))
		})

		It("should parse image without explicit registry", func() {
			registry, image, tag, err := client.ConvertImageRef(ctx, "library/nginx:latest")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Docker Hub"))
			Expect(image).To(Equal("library/nginx"))
			Expect(tag).To(Equal("latest"))
		})

		It("should parse single name image", func() {
			registry, image, tag, err := client.ConvertImageRef(ctx, "nginx")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Docker Hub"))
			Expect(image).To(Equal("nginx"))
			Expect(tag).To(Equal("latest"))
		})

		It("should parse image with tag", func() {
			registry, image, tag, err := client.ConvertImageRef(ctx, "nginx:1.21.0")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Docker Hub"))
			Expect(image).To(Equal("nginx"))
			Expect(tag).To(Equal("1.21.0"))
		})

		It("should parse official image shorthand", func() {
			registry, image, tag, err := client.ConvertImageRef(ctx, "ubuntu")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Docker Hub"))
			Expect(image).To(Equal("ubuntu"))
			Expect(tag).To(Equal("latest"))
		})
	})

	Describe("Cloud provider registries", func() {
		It("should parse GCR image with tag", func() {
			registry, image, tag, err := client.ConvertImageRef(ctx, "gcr.io/project/image:v1.0.0")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("GCR"))
			Expect(image).To(Equal("project/image"))
			Expect(tag).To(Equal("v1.0.0"))
		})

		It("should parse ECR-style registry", func() {
			registry, image, tag, err := client.ConvertImageRef(ctx, "123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp:latest")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("AWS ECR"))
			Expect(image).To(Equal("myapp"))
			Expect(tag).To(Equal("latest"))
		})

		It("should parse Azure Container Registry", func() {
			registry, image, tag, err := client.ConvertImageRef(ctx, "myregistry.azurecr.io/samples/nginx:latest")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Azure ACR"))
			Expect(image).To(Equal("samples/nginx"))
			Expect(tag).To(Equal("latest"))
		})

		It("should parse Quay.io image", func() {
			registry, image, tag, err := client.ConvertImageRef(ctx, "quay.io/prometheus/prometheus:v2.30.0")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Quay"))
			Expect(image).To(Equal("prometheus/prometheus"))
			Expect(tag).To(Equal("v2.30.0"))
		})
	})

	Describe("Custom registries", func() {
		It("should parse registry with port", func() {
			registry, image, tag, err := client.ConvertImageRef(ctx, "registry.io:5000/team/project/image:tag")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Custom Registry"))
			Expect(image).To(Equal("team/project/image"))
			Expect(tag).To(Equal("tag"))
		})

		It("should parse registry with port and no tag", func() {
			registry, image, tag, err := client.ConvertImageRef(ctx, "registry.io:5000/image")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Custom Registry"))
			Expect(image).To(Equal("image"))
			Expect(tag).To(Equal("latest"))
		})

		It("should parse registry with subdomain", func() {
			registry, image, tag, err := client.ConvertImageRef(ctx, "eu.gcr.io/project-id/image:tag")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("GCR EU"))
			Expect(image).To(Equal("project-id/image"))
			Expect(tag).To(Equal("tag"))
		})

		It("should parse registry with hyphen in name", func() {
			registry, image, tag, err := client.ConvertImageRef(ctx, "my-registry.io/app:v1")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("My Registry"))
			Expect(image).To(Equal("app"))
			Expect(tag).To(Equal("v1"))
		})
	})

	Describe("Image formats", func() {
		It("should parse image with digest", func() {
			registry, image, tag, err := client.ConvertImageRef(ctx, "docker.io/library/alpine@sha256:abcd1234")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Docker Hub"))
			Expect(image).To(Equal("library/alpine"))
			Expect(tag).To(Equal("latest"))
		})

		It("should parse image with tag and digest", func() {
			registry, image, tag, err := client.ConvertImageRef(ctx, "gcr.io/project/image:v1.0@sha256:abcd1234")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("GCR"))
			Expect(image).To(Equal("project/image"))
			Expect(tag).To(Equal("v1.0"))
		})

		It("should parse multi-level namespace", func() {
			registry, image, tag, err := client.ConvertImageRef(ctx, "registry.io/team/project/subproject/image:tag")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Custom Registry"))
			Expect(image).To(Equal("team/project/subproject/image"))
			Expect(tag).To(Equal("tag"))
		})

		It("should parse image with complex tag", func() {
			registry, image, tag, err := client.ConvertImageRef(ctx, "docker.io/library/app:v1.2.3-alpha.1")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Docker Hub"))
			Expect(image).To(Equal("library/app"))
			Expect(tag).To(Equal("v1.2.3-alpha.1"))
		})

		It("should default to latest when no tag specified", func() {
			registry, image, tag, err := client.ConvertImageRef(ctx, "gcr.io/project/image")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("GCR"))
			Expect(image).To(Equal("project/image"))
			Expect(tag).To(Equal("latest"))
		})

		It("should parse image with underscores and hyphens", func() {
			registry, image, tag, err := client.ConvertImageRef(ctx, "docker.io/my_org/my-app_v2:1.0.0-rc1")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Docker Hub"))
			Expect(image).To(Equal("my_org/my-app_v2"))
			Expect(tag).To(Equal("1.0.0-rc1"))
		})

		It("should parse image with SHA-like tag", func() {
			registry, image, tag, err := client.ConvertImageRef(ctx, "docker.io/library/app:sha-abcd1234")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Docker Hub"))
			Expect(image).To(Equal("library/app"))
			Expect(tag).To(Equal("sha-abcd1234"))
		})
	})

	Describe("Edge cases", func() {
		It("should parse image path with many slashes", func() {
			registry, image, tag, err := client.ConvertImageRef(ctx, "gcr.io/a/b/c/d/e/image:tag")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("GCR"))
			Expect(image).To(Equal("a/b/c/d/e/image"))
			Expect(tag).To(Equal("tag"))
		})

		It("should parse numeric tag", func() {
			registry, image, tag, err := client.ConvertImageRef(ctx, "docker.io/app:12345")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Docker Hub"))
			Expect(image).To(Equal("app"))
			Expect(tag).To(Equal("12345"))
		})

		It("should parse tag with special characters", func() {
			registry, image, tag, err := client.ConvertImageRef(ctx, "docker.io/app:v1.0_beta-rc.1+build.123")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Docker Hub"))
			Expect(image).To(Equal("app"))
			Expect(tag).To(Equal("v1.0_beta-rc.1+build.123"))
		})
	})
})
