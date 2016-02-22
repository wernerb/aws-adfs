package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	flag "github.com/ogier/pflag"

	"github.com/andelf/go-curl"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/go-ini/ini"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	errSharedCredentialsHomeNotFound = "user home directory not found."
)

//CGO_LDFLAGS="-L/usr/local/opt/curl/lib -lcurl -lssl -lcrypto -lssl -lcrypto -lldap -lz" go install -a github.com/wernerb

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func doSAML(assertion string, svc *sts.STS) *sts.AssumeRoleWithSAMLOutput {
	r := base64.NewDecoder(base64.StdEncoding, strings.NewReader(assertion))
	buf := new(bytes.Buffer)
	buf.ReadFrom(r)
	s := buf.String()
	// fmt.Println(assertion)

	re1, _ := regexp.Compile(`<AttributeValue>(arn:.*?),(arn:.*?)<\/AttributeValue>`) // Prepare our regex
	resultSlice := re1.FindAllStringSubmatch(s, -1)
	// fmt.Printf("%v", resultSlice)

	//TODO: Support multiple roles, allow selection between them.
	// fmt.Println(resultSlice[0][1])
	// fmt.Println(resultSlice[0][2])

	var principalArn string
	var roleArn string

	if strings.Contains(resultSlice[0][1], "saml-provider") == true {
		principalArn = resultSlice[0][1]
		roleArn = resultSlice[0][2]
	} else {
		principalArn = resultSlice[0][2]
		roleArn = resultSlice[0][1]
	}

	params := &sts.AssumeRoleWithSAMLInput{
		PrincipalArn:  aws.String(principalArn), // Required
		RoleArn:       aws.String(roleArn),      // Required
		SAMLAssertion: aws.String(assertion),    // Required
	}
	// fmt.Println(params)

	resp, err := svc.AssumeRoleWithSAML(params)

	if err != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err.Error())
	}
	return resp

}

func writeData(ptr []byte, userdata interface{}) bool {
	ch, ok := userdata.(chan string)
	if ok {
		ch <- string(ptr)
		return true // ok
	}
	println("ERROR!")
	return false
}

func inputCredentials(optUsername *string) (string, string) {
	reader := bufio.NewReader(os.Stdin)

	var username = *optUsername
	if username == "" {
		// ask for username
		fmt.Println("enter username: ")
		username, _ = reader.ReadString('\n')
	}

	fmt.Println("enter password: ")
	bytePassword, _ := terminal.ReadPassword(int(syscall.Stdin))
	password := string(bytePassword)

	return strings.TrimSpace(username), strings.TrimSpace(password)
}

func getIniLocation() string {
	if filename := os.Getenv("AWS_SHARED_CREDENTIALS_FILE"); filename != "" {
		return filename
	}

	homeDir := os.Getenv("HOME") // *nix
	if homeDir == "" {           // Windows
		homeDir = os.Getenv("USERPROFILE")
	}
	if homeDir == "" {
		fmt.Println("home folder not found")
		os.Exit(1)
		return ""
	}

	return filepath.Join(homeDir, ".aws", "credentials")
}

func writeIni(sectionName string, credentials *sts.AssumeRoleWithSAMLOutput) {
	iniLocation := getIniLocation()

	var cfg *ini.File
	if _, err := os.Stat(iniLocation); os.IsNotExist(err) {
		fmt.Printf("No config file found at: %s. Creating new one.\n", iniLocation)
		cfg = ini.Empty()
	} else {
		cfg, err = ini.Load(iniLocation)
		if err != nil {
			fmt.Println(err.Error())
		}
	}

	cfg.NewSection(sectionName)
	cfg.Section(sectionName).NewKey("aws_access_key_id", aws.StringValue(credentials.Credentials.AccessKeyId))
	cfg.Section(sectionName).NewKey("aws_secret_access_key", aws.StringValue(credentials.Credentials.SecretAccessKey))
	cfg.Section(sectionName).NewKey("aws_session_token", aws.StringValue(credentials.Credentials.SessionToken))
	cfg.SaveTo(iniLocation)

}

func main() {

	optDebug := flag.BoolP("debug", "d", false, "display debug info")

	optURL := flag.StringP("idp", "i", os.Getenv("AWSADFS_IDPURL"), "set adfs idp url. alternatively set AWSADFS_IDPURL. for example: https://sts.company.com/adfs/ls/idpinitiatedsignon.aspx?loginToRp=urn:amazon:webservices")

	optUsername := flag.StringP("username", "u", os.Getenv("AWSADFS_USERNAME"), "username to log in with. alternatively set AWSADFS_USERNAME; prompted by default")

	optIni := flag.BoolP("save", "s", true, "save to aws/credentials")

	optIniProfile := flag.StringP("profile", "p", os.Getenv("AWSADFS_PROFILE"), "profile name in ~/.aws/credentials. If empty uses role-arn. alternatively, set AWSADFS_PROFILE")

	optOpenSSL := flag.StringP("opensslconf", "o", os.Getenv("AWSADFS_OPENSSL_CONF"), "path to openssl.cnf configuration with pkcs11 engine defined. alternatively, set AWSADFS_OPENSSL_CONF. uses system openssl.cnf as default.")

	optCAfile := flag.StringP("cacert", "c", os.Getenv("AWSADFS_CAFILE"), "path to CA file to use when connecting. alternatively, set AWSADFS_CAFILE")

	flag.Parse()

	if *optOpenSSL != "" {
		if _, err := os.Stat(*optOpenSSL); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "ERROR: path to cacert does not exist")
			flag.PrintDefaults()
			os.Exit(1)
		}
		// Set OPENSSL_CONF locally in program
		os.Setenv("OPENSSL_CONF", *optOpenSSL)
	}

	if *optURL == "" {
		fmt.Fprintf(os.Stderr, "ERROR: set AWSADFS_IDPURL to an sts url. for example \"https://sts.company.com/adfs/ls/idpinitiatedsignon.aspx?loginToRp=urn:amazon:webservices\"\n\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *optCAfile != "" {
		if _, err := os.Stat(*optCAfile); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "ERROR: path to cacert does not exist")
			flag.PrintDefaults()
			os.Exit(1)
		}
	}

	if *optIni == true && *optIniProfile == "" {
		fmt.Fprintf(os.Stderr, "ERROR: saving to ini requires setting a profile name with the -profile flag.")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *optDebug == true {
		ver := curl.VersionInfo(curl.VERSION_NOW)
		fmt.Println(ver.Protocols)
		fmt.Printf("VersionInfo: Age: %d, Version:%s, Host:%s, Features:%d, SslVer: %s, SslVerNum: %d, LibzV: %s, ssh: %s\n",
			ver.Age, ver.Version, ver.Host, ver.Features, ver.SslVersion, ver.SslVersionNum, ver.LibzVersion, ver.LibsshVersion)
	}

	username, password := inputCredentials(optUsername)

	easy := curl.EasyInit()
	defer easy.Cleanup()

	easy.Setopt(curl.OPT_URL, *optURL)

	easy.Setopt(curl.OPT_COOKIEJAR, "")
	easy.Setopt(curl.OPT_FOLLOWLOCATION, true)
	// Unfortunately, the smartcard dynamic library doesn't understand
	//  TLS 1.2 and would error out. Therefore we are limiting to TLS 1.1.
	easy.Setopt(curl.OPT_SSLVERSION, 5) //SSL_TLS_1.1
	easy.Setopt(curl.OPT_VERBOSE, *optDebug)
	easy.Setopt(curl.OPT_SSLENGINE, "pkcs11")
	easy.Setopt(curl.OPT_NOPROGRESS, true)
	easy.Setopt(curl.OPT_SSLENGINE_DEFAULT, 1)
	easy.Setopt(curl.OPT_SSL_VERIFYPEER, 1)
	easy.Setopt(curl.OPT_SSLKEYTYPE, "ENG")
	easy.Setopt(curl.OPT_SSLCERTTYPE, "ENG")
	easy.Setopt(curl.OPT_WRITEFUNCTION, writeData)
	if *optCAfile != "" {
		easy.Setopt(curl.OPT_CAINFO, *optCAfile)
	}

	// make a chan for first response
	ch := make(chan string, 100)
	easy.Setopt(curl.OPT_WRITEDATA, ch)

	formpostdata := "UserName=" + username + "&Password=" + password + "&AuthMethod=FormsAuthentication"
	easy.Setopt(curl.OPT_POSTFIELDS, formpostdata)

	if err := easy.Perform(); err != nil {
		fmt.Printf("ERROR: %v\n", err)
	}

	data := <-ch
	re, _ := regexp.Compile(`(Welkom|Welcome).(.*?)<\/div>`)
	if re.MatchString(data) == true {
		fmt.Println("... logged in")
	} else {
		fmt.Println("... could not log in; exiting")
		fmt.Println(data)
		os.Exit(1)
	}

	//TODO: Support non-smartcard authentication. I.e., detect if certificate is asked at all.
	certpostdata := "AuthMethod=CertificateAuthentication&RetrieveCertificate=1"
	easy.Setopt(curl.OPT_POSTFIELDS, certpostdata)

	svc := sts.New(session.New())

	// make a chan for second response
	ch2 := make(chan string, 100)
	easy.Setopt(curl.OPT_WRITEDATA, ch2)

	if err := easy.Perform(); err != nil {
		fmt.Printf("ERROR: %v\n", err)
	}

	data2 := <-ch2
	re2, _ := regexp.Compile(`SAMLResponse".*?value="(.*?)"`)
	out := re2.FindStringSubmatch(data2)
	assertion := out[1]
	output := doSAML(assertion, svc)

	os.Setenv("AWS_ACCESS_KEY_ID", aws.StringValue(output.Credentials.AccessKeyId))
	os.Setenv("AWS_SECRET_ACCESS_KEY", aws.StringValue(output.Credentials.SecretAccessKey))
	os.Setenv("AWS_SESSION_TOKEN", aws.StringValue(output.Credentials.SessionToken))
	os.Setenv("AWS_SECURITY_TOKEN", aws.StringValue(output.Credentials.SessionToken))

	fmt.Printf("export AWS_ACCESS_KEY_ID=%s\n", os.Getenv("AWS_ACCESS_KEY_ID"))
	fmt.Printf("export AWS_SECRET_ACCESS_KEY=%s\n", os.Getenv("AWS_SECRET_ACCESS_KEY"))
	fmt.Printf("export AWS_SESSION_TOKEN=%s\n", os.Getenv("AWS_SESSION_TOKEN"))
	fmt.Printf("export AWS_SECURITY_TOKEN=\"$AWS_SESSION_TOKEN\"\n")

	if *optIni == true {
		writeIni(*optIniProfile, output)
	}

}
