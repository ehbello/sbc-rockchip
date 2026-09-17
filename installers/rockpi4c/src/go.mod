module rockpi4c

go 1.26.5

require (
	github.com/siderolabs/talos/pkg/machinery v1.14.0
	golang.org/x/sys v0.47.0
)

require go.yaml.in/yaml/v4 v4.0.0-rc.6 // indirect

replace github.com/siderolabs/talos/pkg/machinery => github.com/ehbello/talos/pkg/machinery v1.14.0-rc.2.0.20260903091643-7386b17fbf6e
