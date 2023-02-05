package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/smithy-go"
	"go.uber.org/zap"
	"net/smtp"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"log"
	"net/http"
	"strings"

	"github.com/mholt/acmez"
	"github.com/mholt/acmez/acme"
)

// Run pebble (the ACME server) before running this example:
//
// PEBBLE_VA_ALWAYS_VALID=1 pebble -config ./test/config/pebble-config.json -strict

type MyEvent struct {
	Name string `json:"name"`
}

type CertificateType string

const (
	EndpointCertificate  CertificateType = "certificate"
	CertificateAuthority CertificateType = "ca"
)

type Certificate struct {
	Pem                string          `json:"pem"`
	CertType           CertificateType `json:"certType"`
	NotAfterTimeMillis int64           `json:"notAfterTimeMillis"`
	NotAfterTime       time.Time       `json:"notAfterTime"`
	NotBeforeInMillis  int64           `json:"notBeforeInMillis"`
	NotBeforeTime      time.Time       `json:"notBeforeTime"`
}

type Certificates struct {
	Domain     string        `json:"domain"`
	PrivateKey string        `json:"privateKey"`
	Certs      []Certificate `json:"certs"`
}

func main() {
	lambda.Start(HandleRequest)
}

func HandleRequest(ctx context.Context, name MyEvent) (string, error) {
	// read domain names from account --done
	// read existing certificates from secrets named wildcard.${domainName} --done
	// if secret does not exist or its within 30 days of expiration generate new set of certificates using new key, let old key expire --done
	// store new structure for each domain in secrets manager --done
	// process will run daily to ensure that within the 30 days before expiring, the cert is created.
	// push alert if unable to generate

	var results []string

	certsEmailAddress := os.Getenv("CERTS_EMAIL")
	if certsEmailAddress == "" {
		return "error", fmt.Errorf("CERTS_EMAIL address environment variable is required")
	}
	daysBeforeExpiringRenewal := int64(91)

	client, err := getRoute53Client()
	maxZone := int32(350)
	listZonesInput := route53.ListHostedZonesInput{
		MaxItems: &maxZone,
	}
	listOutput, err := client.ListHostedZones(context.Background(), &listZonesInput)
	if err != nil {
		log.Fatal(err)
	}

	//continue on failures
	for _, zone := range listOutput.HostedZones {

		secretClient, err := getRouteSecretsManagerClient()
		if err != nil {
			return *zone.Name, err

		}
		zoneName := *zone.Name
		zoneName = zoneName[:len(zoneName)-1]
		secretName := "cert.wildcard." + zoneName
		secretDesc := "Automatically maintained wildcard certs for domain"
		createSecretInput := secretsmanager.CreateSecretInput{
			Name:                        &secretName,
			Description:                 &secretDesc,
			ForceOverwriteReplicaSecret: false,
		}
		secretIsPresent := false
		_, err = secretClient.CreateSecret(context.Background(), &createSecretInput)
		if err != nil {
			var oe *smithy.OperationError
			if errors.As(err, &oe) {
				oErr := oe.Error()
				if strings.Contains(strings.ToLower(oErr), "resourceexistsexception") {
					secretIsPresent = true
				} else {
					return *zone.Name, err

				}
			} else {
				return "err", fmt.Errorf("domain:%s err:%w", *zone.Name, err)

			}

		}
		expiredCertV := false
		expiredCert := &expiredCertV
		if secretIsPresent {
			expiredCert, err = isCertificateExpiring(secretClient, &secretName, daysBeforeExpiringRenewal)
			if err != nil {
				return "error", fmt.Errorf("domain:%s err:%w", *zone.Name, err)

			}
		}

		if !secretIsPresent || *expiredCert {
			certs, err := getCertsFromACME(*zone.Name, certsEmailAddress)
			if err != nil {
				return "error", fmt.Errorf("domain:%s err:%w", *zone.Name, err)

			}

			certConent, err := json.Marshal(certs)
			if err != nil {
				return "error", fmt.Errorf("domain:%s err:%w", *zone.Name, err)
			}
			certConentString := string(certConent)
			putSecretInput := secretsmanager.PutSecretValueInput{
				SecretId:     &secretName,
				SecretString: &certConentString,
			}
			putSecretValueOutput, err := secretClient.PutSecretValue(context.Background(), &putSecretInput)
			if err != nil {
				return "error", fmt.Errorf("domain:%s err:%w", *zone.Name, err)
			}
			log.Printf("SecretManager putsecretVal output: %v", putSecretValueOutput)

			_, err = json.MarshalIndent(certs, "", "   ")
			if err != nil {
				return "error", fmt.Errorf("domain:%s err:%w", *zone.Name, err)
			}
			results = append(results, fmt.Sprintf("domain:%s certificate renewed!", *zone.Name))
		} else {
			results = append(results, fmt.Sprintf("Certificate is expiring in longer than %d days, no action taken", daysBeforeExpiringRenewal))
		}

	}

	log.Printf("results: \n%s", strings.Join(results, "\n"))

	return strings.Join(results, "\n"), nil

}

func isCertificateExpiring(client *secretsmanager.Client, secretName *string, daysBeforeExpiringRenewal int64) (*bool, error) {

	result := false
	found := false

	getValueInput := secretsmanager.GetSecretValueInput{
		SecretId: secretName,
	}
	secretVal, err := client.GetSecretValue(context.Background(), &getValueInput)
	if err != nil {
		//error reading value, so we will induce recreation by calling the certificate expire
		result = true
		log.Printf("error retreiving certificate from secretsmanager, we will default to replacing the value")
		return &result, nil

	}
	cert := Certificates{}
	err = json.Unmarshal([]byte(*secretVal.SecretString), &cert)
	if err != nil {
		return nil, err
	}

	nowPlusDaysInMillis := time.Now().UnixMilli() + (time.Hour.Milliseconds() * 24 * daysBeforeExpiringRenewal)
	for _, certificate := range cert.Certs {
		if certificate.CertType == EndpointCertificate {
			found = true
			if certificate.NotAfterTimeMillis <= nowPlusDaysInMillis {
				result = true
			}
		}
	}
	if !found {
		result = true
	}
	return &result, nil

}

func getCertsFromACME(hostName, emailAddress string) (*Certificates, error) {
	// Put your domains here
	if len(hostName) == 0 {
		return nil, fmt.Errorf("there are no domains to generate certificates for")
	}
	if hostName[len(hostName)-1:] == "." {
		hostName = hostName[:len(hostName)-1]
	}
	domains := []string{"*." + hostName}

	// A context allows us to cancel long-running ops
	ctx := context.Background()

	// Logging is important - replace with your own zap logger
	logger, err := zap.NewDevelopment()
	if err != nil {
		return nil, err
	}

	client := acmez.Client{
		Client: &acme.Client{
			//Directory: "https://acme-staging-v02.api.letsencrypt.org/directory", // default pebble endpoint
			Directory: "https://acme-v02.api.letsencrypt.org/directory",
			HTTPClient: &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true, // REMOVE THIS FOR PRODUCTION USE!
					},
				},
			},
			Logger: logger,
		},
		ChallengeSolvers: map[string]acmez.Solver{
			acme.ChallengeTypeHTTP01:    nil,        // provide these!
			acme.ChallengeTypeDNS01:     mySolver{}, // provide these!
			acme.ChallengeTypeTLSALPN01: nil,        // provide these!
		},
	}

	// Before you can get a cert, you'll need an account registered with
	// the ACME CA; it needs a private key which should obviously be
	// different from any key used for certificates!
	accountPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating account key: %v", err)
	}
	account := acme.Account{
		Contact:              []string{fmt.Sprintf("mailto:%s", emailAddress)},
		TermsOfServiceAgreed: true,
		PrivateKey:           accountPrivateKey,
	}

	// If the account is new, we need to create it; only do this once!
	// then be sure to securely store the account key and metadata so
	// you can reuse it later!
	account, err = client.NewAccount(ctx, account)
	if err != nil {
		return nil, fmt.Errorf("new account: %v", err)
	}

	// Every certificate needs a key.
	certPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating certificate key: %v", err)
	}

	// Once your client, account, and certificate key are all ready,
	// it's time to request a certificate! The easiest way to do this
	// is to use ObtainCertificate() and pass in your list of domains
	// that you want on the cert. But if you need more flexibility, you
	// should create a CSR yourself and use ObtainCertificateUsingCSR().

	certs, err := client.ObtainCertificate(ctx, account, certPrivateKey, domains)
	if err != nil {
		return nil, fmt.Errorf("obtaining certificate: %v", err)
	}

	// ACME servers should usually give you the entire certificate chain
	// in PEM format, and sometimes even alternate chains! It's up to you
	// which one(s) to store and use, but whatever you do, be sure to
	// store the certificate and key somewhere safe and secure, i.e. don't
	// lose them!
	certsToStoreList := []Certificates{}

	for _, cert := range certs {
		certsToStore := Certificates{}
		certsToStore.PrivateKey = encode(certPrivateKey)
		certsToStore.Domain = hostName
		b, rest := pem.Decode(cert.ChainPEM)
		for b != nil {
			x509Cert, err := x509.ParseCertificates(b.Bytes)
			if err != nil {
				return nil, err
			}
			certType := EndpointCertificate
			if x509Cert[0].IsCA {
				certType = CertificateAuthority
			}

			certsToStore.Certs = append(certsToStore.Certs, Certificate{
				Pem:                string(pem.EncodeToMemory(b)),
				CertType:           certType,
				NotAfterTimeMillis: x509Cert[0].NotAfter.UnixMilli(),
				NotAfterTime:       x509Cert[0].NotAfter,
				NotBeforeInMillis:  x509Cert[0].NotBefore.UnixMilli(),
				NotBeforeTime:      x509Cert[0].NotBefore,
			})
			b, rest = pem.Decode(rest)
		}
		certsToStoreList = append(certsToStoreList, certsToStore)

	}
	//toPrint, err := json.MarshalIndent(certsToStore, "", "   ")
	if err != nil {
		return nil, err
	}

	if len(certsToStoreList) == 0 {
		return nil, fmt.Errorf("expected once certificate bundle from the ACME service, but got %d", len(certsToStoreList))
	}

	resultingCerts := combineCerts(certsToStoreList)

	return &resultingCerts, nil
}

func combineCerts(certificates []Certificates) Certificates {

	var result = Certificates{}
	for i := 0; i < len(certificates); i++ {
		result.Domain = certificates[i].Domain
		if result.PrivateKey == "" {
			result.PrivateKey = certificates[i].PrivateKey
		}
		for _, cert := range certificates[i].Certs {
			if !isCertInList(result, cert) {
				result.Certs = append(result.Certs, cert)
			}
		}
	}
	return result

}

func isCertInList(certList Certificates, cert Certificate) bool {
	found := false
	for _, lsCert := range certList.Certs {
		if cert.Pem == lsCert.Pem {
			found = true
			break
		}
	}
	log.Printf("certificate already in list: %v", found)
	return found
}

// mySolver is a no-op acmez.Solver for example purposes only.
type mySolver struct{}

func (s mySolver) Present(ctx context.Context, chal acme.Challenge) error {

	nameParts := strings.Split(chal.DNS01TXTRecordName(), ".")
	domainName := nameParts[1] + "." + nameParts[2]

	fullRecordName := chal.DNS01TXTRecordName()
	valueToStore := "\"" + chal.DNS01KeyAuthorization() + "\""
	client, err := getRoute53Client()
	if err != nil {
		return err
	}

	err = s.createRoute53Record(domainName, err, client, fullRecordName, valueToStore)

	if err != nil {
		return err
	}

	startTimeInSeconds := time.Now().UnixMilli() / 1000
	for true {
		time.Sleep(time.Second * 10)
		timeInSeconds := time.Now().UnixMilli() / 1000
		log.Printf("Waiting for the records to propogate.  5 minute, waited for %d seconds", timeInSeconds-startTimeInSeconds)
		if timeInSeconds-startTimeInSeconds >= 300 {
			break
		}
	}

	return nil
}

func getRoute53Client() (*route53.Client, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, err
	}
	client := route53.NewFromConfig(cfg)

	return client, nil
}
func getRouteSecretsManagerClient() (*secretsmanager.Client, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, err
	}
	client := secretsmanager.NewFromConfig(cfg)

	return client, nil
}

func (s mySolver) createRoute53Record(domainName string, err error, client *route53.Client, fullRecordName, valueToStore string) error {
	//recordName:=nameParts[0]
	listHostedZoneIn := route53.ListHostedZonesByNameInput{DNSName: &domainName}
	listHostedZoneOut, err := client.ListHostedZonesByName(context.Background(), &listHostedZoneIn)
	if err != nil {
		return fmt.Errorf("route53: Erro listing zones for the domain: %w", err)
	}

	hostedZoneId := listHostedZoneOut.HostedZones[0].Id

	listCurrentDataInput := route53.ListResourceRecordSetsInput{
		HostedZoneId:    hostedZoneId,
		StartRecordName: &fullRecordName,

		StartRecordType: types.RRTypeTxt,
	}

	changeRSetInput := route53.ChangeResourceRecordSetsInput{
		ChangeBatch: &types.ChangeBatch{
			Changes: []types.Change{
				{
					Action: types.ChangeActionUpsert,
					ResourceRecordSet: &types.ResourceRecordSet{
						Name: &fullRecordName,
						Type: types.RRTypeTxt,
						ResourceRecords: []types.ResourceRecord{
							{
								Value: &valueToStore,
							},
						},
						TTL: aws.Int64(300),
					},
				},
			},
			Comment: aws.String("Upserting NS record in parent zone"),
		},
		HostedZoneId: hostedZoneId,
	}
	currentRecords, err := client.ListResourceRecordSets(context.Background(), &listCurrentDataInput)
	if err != nil {
		return fmt.Errorf("route53: Erro listing current record: %w", err)
	}
	log.Printf("%v", *currentRecords)

	for _, set := range currentRecords.ResourceRecordSets {

		if fullRecordName+"." == *set.Name {
			for _, record := range set.ResourceRecords {
				changeRSetInput.ChangeBatch.Changes[0].ResourceRecordSet.ResourceRecords = append(changeRSetInput.ChangeBatch.Changes[0].ResourceRecordSet.ResourceRecords, types.ResourceRecord{Value: record.Value})
			}
		}
	}

	_, err = client.ChangeResourceRecordSets(context.Background(), &changeRSetInput)
	if err != nil {
		return fmt.Errorf("route53: Error making changes to the record (ChangeResourceRecordSets): %w", err)
	}
	return nil
}

func (s mySolver) CleanUp(ctx context.Context, chal acme.Challenge) error {
	log.Printf("[DEBUG] cleanup: %#v", chal)

	fullRecordName := chal.DNS01TXTRecordName()
	valueToStore := "\"" + chal.DNS01KeyAuthorization() + "\""
	nameParts := strings.Split(chal.DNS01TXTRecordName(), ".")
	domainName := nameParts[1] + "." + nameParts[2]

	client, err := getRoute53Client()
	if err != nil {
		return err
	}

	listHostedZoneIn := route53.ListHostedZonesByNameInput{DNSName: &domainName}
	listHostedZoneOut, err := client.ListHostedZonesByName(context.Background(), &listHostedZoneIn)
	if err != nil {
		return fmt.Errorf("route53: Erro listing zones for the domain: %w", err)
	}

	hostedZoneId := listHostedZoneOut.HostedZones[0].Id

	listCurrentDataInput := route53.ListResourceRecordSetsInput{
		HostedZoneId:    hostedZoneId,
		StartRecordName: &fullRecordName,

		StartRecordType: types.RRTypeTxt,
	}
	currentRecords, err := client.ListResourceRecordSets(context.Background(), &listCurrentDataInput)
	if err != nil {
		return err
	}

	var indecesToDelete []int

	var resourceRecords []types.ResourceRecord
	var remainingRecords []types.ResourceRecord
	for _, set := range currentRecords.ResourceRecordSets {
		for i, resourceRecord := range set.ResourceRecords {
			if *resourceRecord.Value == valueToStore {
				indecesToDelete = append(indecesToDelete, i)
			}
		}
		for i := 0; i < len(indecesToDelete); i++ {
			r := indecesToDelete[i]

			resourceRecords = append(resourceRecords, set.ResourceRecords[r])
			copy(set.ResourceRecords[r:], set.ResourceRecords[r+1:]) // Shift a[i+1:] left one index.

			set.ResourceRecords[len(set.ResourceRecords)-1] = types.ResourceRecord{} // Erase last element (write zero value).
			set.ResourceRecords = set.ResourceRecords[:len(set.ResourceRecords)-1]
			remainingRecords = append(remainingRecords, set.ResourceRecords...)

		}
		indecesToDelete = []int{}
	}
	action := types.ChangeActionUpsert
	resourceRecordsToChange := remainingRecords
	if len(remainingRecords) == 0 {
		action = types.ChangeActionDelete
		resourceRecordsToChange = resourceRecords

	}
	changeRSetInput := route53.ChangeResourceRecordSetsInput{
		ChangeBatch: &types.ChangeBatch{
			Changes: []types.Change{
				{
					Action: action,
					ResourceRecordSet: &types.ResourceRecordSet{
						Name:            &fullRecordName,
						Type:            types.RRTypeTxt,
						ResourceRecords: resourceRecordsToChange,
						TTL:             aws.Int64(300),
					},
				},
			},
			Comment: aws.String("Upserting NS record in parent zone"),
		},
		HostedZoneId: hostedZoneId,
	}
	_, err = client.ChangeResourceRecordSets(context.Background(), &changeRSetInput)

	return err
}

func encode(privateKey *ecdsa.PrivateKey) string {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	return string(pemEncoded)
}

func sendMail(fromAddress, password, toAddress, subject, body string) {

	message := fmt.Sprintf("From: %s\nTo: %s\n Subject: %s\n\n,%s", fromAddress, toAddress, subject, body)

	err := smtp.SendMail("smtp.gmail.com:587",
		smtp.PlainAuth("", fromAddress, password, "smtp.gmail.com"),
		fromAddress, []string{toAddress}, []byte(message))

	if err != nil {
		log.Printf("smtp error: %s", err)
		return
	}

	log.Print("sent, visit http://foobarbazz.mailinator.com")
}
