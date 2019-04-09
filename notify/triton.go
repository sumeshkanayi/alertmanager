package notify

import (
	"github.com/joyent/triton-go"
	"github.com/joyent/triton-go/authentication"
	"github.com/joyent/triton-go/compute"

	"context"
	"encoding/pem"
	_ "fmt"
	"io/ioutil"
	"log"
	"os"
)

func createTritonInstance(keyID string, accountName string, packageName string, imageName string, networks []string, cloudApi string, services []string) (error,*compute.Instance){
    tagMap:=make(map[string]string)
    tagMap["created_by"]="alert_manager"
	keyMaterial := os.Getenv("TRITON_KEY_MATERIAL")

	var signer authentication.Signer
	var err error

	if keyMaterial == "" {

		input := authentication.SSHAgentSignerInput{
			KeyID:       keyID,
			AccountName: accountName,
		}

		signer, err = authentication.NewSSHAgentSigner(input)
		//signer, err=authentication.NewSSHAgentSigner(input)

		if err != nil {
			log.Fatalf("Error Creating SSH Agent Signer: {{err}}", err)
		}
	} else {
		var keyBytes []byte
		if _, err = os.Stat(keyMaterial); err == nil {
			keyBytes, err = ioutil.ReadFile(keyMaterial)
			if err != nil {
				log.Fatalf("Error reading key material from %s: %s",
					keyMaterial, err)
			}
			block, _ := pem.Decode(keyBytes)
			if block == nil {
				log.Fatalf(
					"Failed to read key material '%s': no key found", keyMaterial)
			}

			if block.Headers["Proc-Type"] == "4,ENCRYPTED" {
				log.Fatalf(
					"Failed to read key '%s': password protected keys are\n"+
						"not currently supported. Please decrypt the key prior to use.", keyMaterial)
			}

		} else {
			keyBytes = []byte(keyMaterial)
		}

		input := authentication.PrivateKeySignerInput{
			KeyID:              keyID,
			PrivateKeyMaterial: keyBytes,
			AccountName:        accountName,
		}
		signer, err = authentication.NewPrivateKeySigner(input)
		if err != nil {
			log.Fatalf("Error Creating SSH Private Key Signer: {{err}}", err)
		}
	}

	config := &triton.ClientConfig{
		TritonURL:   cloudApi,
		AccountName: accountName,
		Signers:     []authentication.Signer{signer},
	}

	c, err := compute.NewClient(config)

	if err != nil {
		log.Fatalf("compute.NewClient: %s", err)
		log.Println("clinet is ", c)
	}
	computeInstance := c.Instances()
	ctx := context.Background()

	cns := compute.InstanceCNS{
		Disable:  false,
		Services: services,
	}
	inputList := &compute.CreateInstanceInput{

		NamePrefix: accountName,
		Package:    packageName,
		Image:      imageName,
		Networks:   networks,
		CNS:        cns,
		Tags:tagMap,
	}
	instanceOut,err:=computeInstance.Create(ctx, inputList)
	return err,instanceOut

}