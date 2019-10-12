package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"path/filepath"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/mholt/certmagic"
	"github.com/spf13/cobra"
)

const (
	acmefile  = "acme.yml"
	delimiter = "."
)

var (
	version  = "dev"
	revision = "none"
	date     = "unknown"

	display bool
)

func main() {
	c := &cobra.Command{
		Use:     "acme",
		Short:   fmt.Sprintf("Reads %s configuration file from the current directory", acmefile),
		Version: fmt.Sprintf("%s - build %.7s @ %s", version, revision, date),
		Args:    cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			//
			// Load
			//

			konf := koanf.New(delimiter)
			err := konf.Load(file.Provider(acmefile), yaml.Parser())
			if err != nil {
				return err
			}

			//
			// Configure ACME
			//

			certmagic.Default.Email = konf.String("email")
			certmagic.Default.Agreed = konf.Bool("agreed")
			if konf.Bool("staging") {
				log.Println("Using staging endpoint")
				certmagic.Default.CA = certmagic.LetsEncryptStagingCA
			}
			certmagic.Default.Storage = &certmagic.FileStorage{Path: konf.String("storage")}

			certmagic.Default.OnEvent = func(event string, data interface{}) {
				log.Printf("Event: %s with data: %v\n", event, data)
			}

			// certmagic.Default.DisableHTTPChallenge = false
			certmagic.Default.DisableTLSALPNChallenge = false

			//
			// Process ACME challenge
			//

			certmagic.CleanStorage(certmagic.Default.Storage, certmagic.CleanStorageOptions{
				ExpiredCerts: true,
			})

			mux := http.NewServeMux()
			mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
				fmt.Fprintf(w, "Lookit my cool website over HTTPS!")
			})

			log.Println("Staring server for domains:", konf.Strings("domains"))
			go func() {
				err = http.ListenAndServe(":80", certmagic.Default.HTTPChallengeHandler(mux))
				log.Fatal(err)
			}()

			err = certmagic.Manage(konf.Strings("domains"))
			if err != nil {
				return err
			}

			if display {
				displayKeys(konf)
			}
			return nil
		},
	}
	c.Flags().BoolVarP(&display, "display-certificates", "", false, "Display on STDOUT the generated certificates")

	if err := c.Execute(); err != nil {
		log.Fatal(err)
	}
}

func displayKeys(konf *koanf.Koanf) {
	ca, err := url.Parse(certmagic.Default.CA)
	if err != nil {
		log.Fatal(err)
	}

	basedir := filepath.Join(konf.String("storage"), "acme", ca.Hostname(), "sites")
	log.Println("Base directory:", basedir)

	for _, domain := range konf.Strings("domains") {
		filename := domain + ".key"
		fmt.Printf("=> %s\n\n", filename)

		payload, err := ioutil.ReadFile(filepath.Join(basedir, domain, filename))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(payload))

		filename = domain + ".crt"
		fmt.Printf("=> %s\n\n", filename)

		payload, err = ioutil.ReadFile(filepath.Join(basedir, domain, filename))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(payload))
	}
}
