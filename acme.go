package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

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
)

type controller struct {
	display bool
	showkey bool
	showcrt bool

	ctx     context.Context
	konf    *koanf.Koanf
	magic   *certmagic.Config
	manager *certmagic.ACMEIssuer
	workdir string
}

func main() {
	ctrl := &controller{
		ctx: context.Background(),
	}

	c := &cobra.Command{
		Use:     "acme",
		Short:   fmt.Sprintf("Reads %s configuration file from the current directory", acmefile),
		Version: fmt.Sprintf("%s - build %.7s @ %s", version, revision, date),
		Args:    cobra.NoArgs,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			ctrl.konf = koanf.New(delimiter)
			return ctrl.konf.Load(file.Provider(acmefile), yaml.Parser())
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := ctrl.configure(); err != nil {
				return err
			}

			if err := ctrl.challenge(); err != nil {
				return err
			}

			if !ctrl.display {
				return nil
			}
			return ctrl.displayKeys()
		},
	}
	c.Flags().BoolVarP(&ctrl.display, "display-certificates", "", false, "Display on STDOUT the generated certificates")

	//

	path := &cobra.Command{
		Use:   "path",
		Short: "Returns path of the given domain",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := ctrl.configure(); err != nil {
				return err
			}

			switch {
			case ctrl.showkey && !ctrl.showcrt:
				fmt.Printf("KEY: %s\n", ctrl.filename(args[0], "key"))
			case !ctrl.showkey && ctrl.showcrt:
				fmt.Printf("CRT: %s\n", ctrl.filename(args[0], "crt"))
			default:
				fmt.Printf("KEY: %s\n", ctrl.filename(args[0], "key"))
				fmt.Printf("CRT: %s\n", ctrl.filename(args[0], "crt"))
			}
			return nil
		},
	}
	path.Flags().BoolVarP(&ctrl.showkey, "key", "", false, "Display on STDOUT the generated key")
	path.Flags().BoolVarP(&ctrl.showcrt, "crt", "", false, "Display on STDOUT the generated crt")
	c.AddCommand(path)

	//

	details := &cobra.Command{
		Use:   "details",
		Short: "Show details of the given crt file",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			payload, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}

			var block *pem.Block
			for {
				block, payload = pem.Decode(payload)

				certificate, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return err
				}

				fmt.Printf("%s->%s->%s\n",
					certificate.Subject.CommonName,
					certificate.NotBefore.Format(time.RFC3339),
					certificate.NotAfter.Format(time.RFC3339),
				)

				if len(payload) == 0 {
					return nil
				}
			}
		},
	}
	c.AddCommand(details)

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

	template := certmagic.ACMEIssuer{
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

	c.manager = certmagic.NewACMEIssuer(c.magic, template)
	c.magic.Issuers = []certmagic.Issuer{c.manager}

	//

	ca, err := url.Parse(c.manager.CA)
	if err != nil {
		return err
	}
	c.workdir = filepath.Join(c.konf.String("storage"), "certificates", ca.Hostname()+"-directory")
	return nil
}

func (c *controller) challenge() error {
	certmagic.CleanStorage(context.Background(), c.magic.Storage, certmagic.CleanStorageOptions{
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

	return c.magic.ManageSync(c.ctx, c.konf.Strings("domains"))
}

func (c *controller) displayKeys() error {
	log.Println("Base directory:", c.workdir)

	for _, domain := range c.konf.Strings("domains") {
		filename := c.filename(domain, "key")
		fmt.Printf("=> %s\n\n", filepath.Base(filename))

		payload, err := ioutil.ReadFile(filename)
		if err != nil {
			return err
		}
		fmt.Println(string(payload))

		//

		filename = c.filename(domain, "crt")
		fmt.Printf("=> %s\n\n", filepath.Base(filename))

		payload, err = ioutil.ReadFile(filename)
		if err != nil {
			return err
		}
		fmt.Println(string(payload))
	}
	return nil
}

func (c *controller) filename(domain, extension string) string {
	return filepath.Join(c.workdir, domain, domain+"."+extension)
}
