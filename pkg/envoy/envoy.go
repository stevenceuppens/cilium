package envoy

import (
	"io/ioutil"
	"log"
	"os/exec"
	"strconv"
)

type Envoy struct {
	cmd     *exec.Cmd
	LogPath string
	ldsSock string
	lds     *LDSServer
	rdsSock string
	rds     *RDSServer
}

func (e *Envoy) AddListener(name string, port uint32, l7rules []AuxRule) {
	e.lds.addListener(name, port, l7rules)
}

func (e *Envoy) UpdateListener(name string, l7rules []AuxRule) {
	e.lds.updateListener(name, l7rules)
}

func (e *Envoy) RemoveListener(name string) {
	e.lds.removeListener(name)
}

func createConfig(filePath string, adminAddress string) {
	config := string("{\n" +
		"  \"listeners\": [],\n" +
		"  \"admin\": { \"access_log_path\": \"/dev/null\",\n" +
		"             \"address\": \"tcp://" + adminAddress + "\" },\n" +
		"  \"cluster_manager\": {\n" +
		"    \"clusters\": []\n" +
		"  }\n" +
		"}\n")

	log.Print("Config: ", config)
	err := ioutil.WriteFile(filePath, []byte(config), 0644)
	if err != nil {
		panic(err)
	}
}

func StartEnvoy(debug bool, adminPort int, stateDir string, logDir string) *Envoy {
	bootstrapPath := stateDir + "bootstrap.pb"
	configPath := stateDir + "envoy-config.json"
	logPath := logDir + "cilium-envoy.log"
	adminAddress := "127.0.0.1:" + strconv.Itoa(adminPort)
	ldsPath := stateDir + "lds.sock"
	rdsPath := stateDir + "rds.sock"
	conf := Envoy{LogPath: logPath, ldsSock: ldsPath, rdsSock: rdsPath}

	// Create configuration
	createBootstrap(bootstrapPath, "envoy1", "cluster1", "version1",
		"ldsCluster", ldsPath, "rdsCluster", rdsPath, "cluster1")
	createConfig(configPath, adminAddress)

	if debug {
		conf.cmd = exec.Command("sh", "-c", "cilium-envoy-debug >"+logPath+" 2>&1 -l debug -c "+configPath+" -b "+bootstrapPath)
	} else {
		conf.cmd = exec.Command("sh", "-c", "cilium-envoy >"+logPath+" 2>&1 -c "+configPath+" -b "+bootstrapPath)
	}

	conf.lds = createLDSServer(ldsPath)
	conf.rds = createRDSServer(rdsPath, conf.lds)
	conf.rds.run()
	conf.lds.run(conf.rds)

	err := conf.cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	log.Print("Envoy process started at pid ", conf.cmd.Process.Pid)
	return &conf
}

func (conf *Envoy) StopEnvoy() {
	log.Print("Stopping Envoy process ", conf.cmd.Process.Pid)
	conf.rds.stop()
	conf.lds.stop()
	err := conf.cmd.Process.Kill()
	if err != nil {
		log.Fatal(err)
	}
	conf.cmd.Wait()
}
