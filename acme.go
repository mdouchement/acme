package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"path/filepath"

	"github.com/caddyserver/certmagic"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
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

type controller struct {
	display bool

	konf    *koanf.Koanf
	magic   *certmagic.Config
	manager *certmagic.ACMEManager
}

func main() {
	ctrl := &controller{}

	c := &cobra.Command{
		Use:     "acme",
		Short:   fmt.Sprintf("Reads %s configuration file from the current directory", acmefile),
		Version: fmt.Sprintf("%s - build %.7s @ %s", version, revision, date),
		Args:    cobra.NoArgs,
		PersistentPreRunE: func(c *cobra.Command, args []string) error {
			ctrl.konf = koanf.New(delimiter)
			return ctrl.konf.Load(file.Provider(acmefile), yaml.Parser())
		},
		RunE: func(c *cobra.Command, args []string) error {
			if err := ctrl.configure(); err != nil {
				return err
			}

			if err := ctrl.challenge(); err != nil {
				return err
			}

			if !display {
				return nil
			}
			return ctrl.displayKeys()
		},
	}
	c.Flags().BoolVarP(&ctrl.display, "display-certificates", "", false, "Display on STDOUT the generated certificates")

	if err := c.Execute(); err != nil {
		log.Fatal(err)
	}
}

func (c *controller) configure() error {
	c.magic = certmagic.NewDefault()
	c.magic.Storage = &certmagic.FileStorage{Path: c.konf.String("storage")}

	switch kt := certmagic.KeyType(c.konf.String("key_type")); kt {
	case certmagic.ED25519:
		fallthrough
	case certmagic.P256:
		fallthrough
	case certmagic.P384:
		fallthrough
	case certmagic.RSA2048:
		fallthrough
	case certmagic.RSA4096:
		fallthrough
	case certmagic.RSA8192:
		c.magic.KeySource = certmagic.StandardKeyGenerator{KeyType: kt}
	default:
		return fmt.Errorf("unsupported key_type: %s", kt)
	}

	c.magic.OnEvent = func(event string, data interface{}) {
		log.Printf("Event: %s with data: %v\n", event, data)
	}

	template := certmagic.ACMEManager{
		Email:  c.konf.String("email"),
		Agreed: c.konf.Bool("agreed"),
		CA:     certmagic.LetsEncryptProductionCA,
		//
		AltHTTPPort:    certmagic.HTTPChallengePort,
		AltTLSALPNPort: certmagic.TLSALPNChallengePort,
		//
		//
		// DisableHTTPChallenge: false,
		DisableTLSALPNChallenge: true,
	}
	if c.konf.Bool("staging") {
		log.Println("Using staging endpoint")
		template.CA = certmagic.LetsEncryptStagingCA
	}

	c.manager = certmagic.NewACMEManager(c.magic, template)
	c.magic.Issuer = c.manager
	c.magic.Revoker = c.manager

	return nil
}

func (c *controller) challenge() error {
	certmagic.CleanStorage(c.magic.Storage, certmagic.CleanStorageOptions{
		ExpiredCerts: true,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "Lookit my cool website over HTTPS!")
	})

	log.Println("Staring server for domains:", c.konf.Strings("domains"))
	go func() {
		err := http.ListenAndServe(":80", c.manager.HTTPChallengeHandler(mux))
		log.Fatal(err)
	}()

	return c.magic.ManageSync(c.konf.Strings("domains"))
}

func (c *controller) displayKeys() error {
	ca, err := url.Parse(c.manager.CA)
	if err != nil {
		return err
	}

	basedir := filepath.Join(c.konf.String("storage"), "certificates", ca.Hostname()+"-directory")
	log.Println("Base directory:", basedir)

	for _, domain := range c.konf.Strings("domains") {
		filename := domain + ".key"
		fmt.Printf("=> %s\n\n", filename)

		payload, err := ioutil.ReadFile(filepath.Join(basedir, domain, filename))
		if err != nil {
			return err
		}
		fmt.Println(string(payload))

		filename = domain + ".crt"
		fmt.Printf("=> %s\n\n", filename)

		payload, err = ioutil.ReadFile(filepath.Join(basedir, domain, filename))
		if err != nil {
			return err
		}
		fmt.Println(string(payload))
	}
	return nil
}
