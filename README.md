AWS ADFS Smartcard
=========

Golang cli tool that allows to fetch temporary STS AWS credentials using SAML from ADFS that requires pkcs11 (smartcards/hsm). The credentials are saved to ~/.aws/credentials and outputted to shell.

This project uses openssl, libcurl, engine_pkcs11, libp11 and hsa been tested with OSX, win32 support is to be expected soon.

#### Installation instructions (OSX)

1. Download the binary from github releases "aws-adfs" and put it in your path such as `/usr/local/bin`
2. `brew install libp11 --HEAD`
3. `brew install engine_pkcs11 --HEAD`
4. `brew install curl --with-openssl`

Configuration 

1. Copy `openssl.cnf.default` to a folder such as `~/.aws/openssl.cnf`
2. Edit the file to replace `MODULE_PATH = PATH_TO_HSM_OR_SMARTCARD_DYLIB` with the path to the dynamic library for your smart-card.
3. Execute `cat /usr/local/etc/openssl/cert.pem > ~/.aws/smartcacert.pem`
4. Append any CA certificates on your smart card (perhaps check your OSX Keychain) to that file.
5. Set configuration either in cli or in environmental variables by putting the following settings in `~/.zshrc` or `~/.bashrc`

  ```
  export AWSADFS_IDPURL="https://sts.company.com:49443/adfs/ls/idpinitiatedsignon.aspx?loginToRp=urn:amazon:webservices"
  export AWSADFS_USERNAME="myusername@company.com"
  export AWSADFS_CAFILE="$HOME/.aws/smartcacert.pem"
  export AWSADFS_OPENSSL_CONF="$HOME/.aws/openssl.cnf"
  export AWSADFS_PROFILE="myprofile"
  ```

#### Usage instructions

```
Usage of aws-adfs:
  -c, --cacert string
    	path to CA file to use when connecting. alternatively, set AWSADFS_CAFILE
  -d, --debug
    	display debug info
  -i, --idp string
    	set adfs idp url. alternatively set AWSADFS_IDPURL. for example: https://sts.company.com/adfs/ls/idpinitiatedsignon.aspx?loginToRp=urn:amazon:webservices
  -o, --opensslconf string
    	path to openssl.cnf configuration with pkcs11 engine defined. alternatively, set AWSADFS_OPENSSL_CONF. uses system openssl.cnf as default.
  -p, --profile string
    	profile name in ~/.aws/credentials. If empty uses role-arn. alternatively, set AWSADFS_PROFILE
  -s, --save
    	save to aws/credentials (default true)
  -u, --username string
    	username to log in with. alternatively set AWSADFS_USERNAME; prompted by default
```

#### Compilation instructions

Execute:

    CGO_LDFLAGS="-L/usr/local/opt/curl/lib -lcurl -lssl -lcrypto -lssl -lcrypto -lldap -lz" go install -a github.com/wernerb/aws-adfs
