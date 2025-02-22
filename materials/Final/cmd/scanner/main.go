package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"plugin"

	"github.com/blackhat-go/bhg/ch-10/plugin-core/scanner"
)

const PluginsDir = "../../plugins"

func main() {
	var (
		files []os.FileInfo
		err   error
		p     *plugin.Plugin
		n     plugin.Symbol
		check scanner.Checker
		res   *scanner.Result
	)
	if files, err = ioutil.ReadDir(PluginsDir); err != nil {
		log.Fatalln(err)
	}

	for idx := range files {
		fmt.Println("Found plugin: " + files[idx].Name())
		if p, err = plugin.Open(PluginsDir + "/" + files[idx].Name()); err != nil {
			log.Fatalln(err)
		}

		if n, err = p.Lookup("New"); err != nil {
			log.Fatalln(err)
		}

		newFunc, ok := n.(func() scanner.Checker)
		if !ok {
			log.Fatalln("Plugin entry point is no good. Expecting: func New() scanner.Checker{ ... }")
		}
		var host string

		fmt.Println("Input desired IP address or leave blank for default:")
		fmt.Scanln(&host)
		if host == "" {
			host = "10.0.1.20"
		}

		check = newFunc()
		res = check.Check(host, 8080)
		if res.Vulnerable {
			log.Println("Host is vulnerable: " + res.Details)
		} else {
			log.Println("Host is NOT vulnerable")
		}
	}
}