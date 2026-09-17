module rockpi4c

go 1.26.5

require (
	github.com/siderolabs/talos/pkg/machinery v1.14.1
	golang.org/x/sys v0.47.0
)

require go.yaml.in/yaml/v4 v4.0.0-rc.6 // indirect

replace github.com/siderolabs/talos/pkg/machinery => github.com/ehbello/talos/pkg/machinery v1.14.2-0.20260825211440-06784ceb70d9
