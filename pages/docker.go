package pages

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/golang/glog"
	"github.com/akshshar/cadvisor/container/docker"
	"github.com/akshshar/cadvisor/info"
	"github.com/akshshar/cadvisor/manager"
)

const DockerPage = "/docker/"

func serveDockerPage(m manager.Manager, w http.ResponseWriter, u *url.URL) error {
	start := time.Now()

	// The container name is the path after the handler
	containerName := u.Path[len(DockerPage):]

	var data *pageData
	if containerName == "" {
		// Get the containers.
		reqParams := info.ContainerInfoRequest{
			NumStats: 0,
		}
		conts, err := m.DockerContainersInfo("/", &reqParams)
		if err != nil {
			return fmt.Errorf("Failed to get container %q with error: %v", containerName, err)
		}
		subcontainers := make([]link, 0, len(conts))
		for _, cont := range conts {
			subcontainers = append(subcontainers, link{
				Text: getContainerDisplayName(cont.ContainerReference),
				Link: path.Join("/docker", docker.ContainerNameToDockerId(cont.ContainerReference.Name)),
			})
		}

		dockerContainersText := "Docker Containers"
		data = &pageData{
			DisplayName: dockerContainersText,
			ParentContainers: []link{
				link{
					Text: dockerContainersText,
					Link: DockerPage,
				}},
			Subcontainers: subcontainers,
		}
	} else {
		// Get the container.
		reqParams := info.ContainerInfoRequest{
			NumStats: 60,
		}
		conts, err := m.DockerContainersInfo(containerName, &reqParams)
		if err != nil {
			return fmt.Errorf("failed to get container %q with error: %v", containerName, err)
		}
		if len(conts) != 1 {
			return fmt.Errorf("received unexpected container for %q: %v", conts)
		}
		cont := conts[0]
		displayName := getContainerDisplayName(cont.ContainerReference)

		// Make a list of the parent containers and their links
		var parentContainers []link
		parentContainers = append(parentContainers, link{
			Text: "Docker containers",
			Link: DockerPage,
		})
		parentContainers = append(parentContainers, link{
			Text: displayName,
			Link: path.Join(DockerPage, docker.ContainerNameToDockerId(cont.Name)),
		})

		// Get the MachineInfo
		machineInfo, err := m.GetMachineInfo()
		if err != nil {
			return err
		}

		data = &pageData{
			DisplayName:        displayName,
			ContainerName:      cont.Name,
			ParentContainers:   parentContainers,
			Spec:               cont.Spec,
			Stats:              cont.Stats,
			MachineInfo:        machineInfo,
			ResourcesAvailable: cont.Spec.HasCpu || cont.Spec.HasMemory || cont.Spec.HasNetwork,
			CpuAvailable:       cont.Spec.HasCpu,
			MemoryAvailable:    cont.Spec.HasMemory,
			NetworkAvailable:   cont.Spec.HasNetwork,
			FsAvailable:        cont.Spec.HasFilesystem,
		}
	}

	err := pageTemplate.Execute(w, data)
	if err != nil {
		glog.Errorf("Failed to apply template: %s", err)
	}

	glog.V(1).Infof("Request took %s", time.Since(start))
	return nil
}
