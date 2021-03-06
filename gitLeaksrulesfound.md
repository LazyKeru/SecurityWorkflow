# GitLeaks rules found

## Alibaba
```
[[rules]]
	description = "Alibaba"
	regex = '''((alibaba|antfin|aliyun|alipay)(-inc|\.net)|intranetproxy\.alipay)'''
	tags = ["key", "Alibaba"]
```
## antfin
```
[[rules]]
	description = "antfin"
	regex = '''(?i)antfin(.{0,20})?(?-i)['\"][0-9a-zA-Z]{35,40}['\"]'''
	tags = ["key", "Antfin"]
```

## Asymmetric Private Key
```
[[rules]]
	description = "Asymmetric Private Key"
	regex = '''-----BEGIN ((EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY( BLOCK)?-----'''
	tags = ["key", "AsymmetricPrivateKey"]
```

## AWS (amazon web services)

### AWS Manager ID
```
[[rules]]
	description = "AWS Manager ID"
	regex = '''(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'''
	tags = ["key", "AWS"]
```

### AWS Secret Key
```
[[rules]]
	description = "AWS Secret Key"
	regex = '''(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]'''
	tags = ["key", "AWS"]
```

### AWS MWS key
```
[[rules]]
	description = "AWS MWS key"
	regex = '''amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'''
	tags = ["key", "AWS", "MWS"]
```

### AWS Access Key
```
[[rules]]
  description = "AWS Access Key"
  regex = '''(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'''
  tags = ["key", "AWS"]
```

### AWS cred file info
```
[[rules]]
  description = "AWS cred file info"
  regex = '''(?i)(aws_access_key_id|aws_secret_access_key)(.{0,20})?=.[0-9a-zA-Z\/+]{20,40}'''
  tags = ["AWS"]
```

## Dynatrace ttoken
```
[[rules]]
    description = "Dynatrace ttoken"
    regex = '''dt0[a-zA-Z]{1}[0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64}'''
    tags = ["key", "Dynatrace"]
```

## EC
```
[[rules]]
  description = "EC"
  regex = '''-----BEGIN EC PRIVATE KEY-----'''
  tags = ["key", "EC"]
```

## Email
```
[[rules]]
  description = "Email"
  regex = '''[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}'''
  tags = ["email"]
  [rules.allowlist]
    files = ['''(?i)bashrc''']
    description = "ignore bashrc emails"
```

## Entropy and regex exemples

### entropy and regex
```
[[rules]]
  description = "entropy and regex"
  regex = '''(?i)key(.{0,20})?['|"][0-9a-zA-Z]{16,45}['|"]'''
  tags = ["entropy"]
  [[rules.Entropies]]
    Min = "4.5"
    Max = "5.7"
  [[rules.Entropies]]
    Min = "5.5"
    Max = "6.3"
```

## Files with keys and credentials
```
[[rules]]
	description = "Files with keys and credentials"
    fileNameRegex = '''(?i)(id_rsa|passwd|id_rsa.pub|pgpass|pem|key|shadow)'''
```

### High Entropy
```
[[rules]]
  description = "High Entropy"
  regex = '''[0-9a-zA-Z-_!{}/=]{4,120}'''
    file = '''(?i)(dump.sql|high-entropy-misc.txt)$'''
  tags = ["entropy"]
  [[rules.Entropies]]
    Min = "4.3"
    Max = "7.0"
  [rules.allowlist]
    description = "ignore ssh key and pems"
    files = ['''(pem|ppk|env)$''']
    paths = ['''(.*)?ssh''']
```

## Facebook

### Facebook access token
```
[[rules]]
description = "Facebook access token"
regex = '''EAACEdEose0cBA[0-9A-Za-z]+'''
tags = ["key", "Facebook"]
```

### Facebook Secret Key
```
[[rules]]
	description = "Facebook Secret Key"
	regex = '''(?i)(facebook|fb)(.{0,20})?(?-i)['\"][0-9a-f]{32}['\"]'''
	tags = ["key", "Facebook"]
```
### Facebook Client ID
```
[[rules]]
	description = "Facebook Client ID"
	regex = '''(?i)(facebook|fb)(.{0,20})?['\"][0-9]{13,17}['\"]'''
	tags = ["key", "Facebook"]
```

## Generic Credential
```
[[rules]]
	description = "Generic Credential"
	regex = '''(?i)(api_key|apikey|secret)(.{0,20})?['|"][0-9a-zA-Z]{16,45}['|"]'''
	tags = ["key", "API", "generic"]
```

## Github

### Github
```
[[rules]]
	description = "Github"
	regex = '''(?i)github(.{0,20})?(?-i)['\"][0-9a-zA-Z]{35,40}['\"]'''
	tags = ["key", "Github"]
```

### Github Token
```
[[rules]]
	description = "Github Token"
	regex = '''(?:^|^commit\/)[0-9a-zA-Z]{35,40}'''
	tags = ["key", "Github Token"]
```

### Github Personal Access Token
```
[[rules]]
    description = "Github Personal Access Token"
    regex = '''ghp_[0-9a-zA-Z]{36}'''
    tags = ["key", "Github"]
```

### Github OAuth Access Token
```
[[rules]]
    description = "Github OAuth Access Token"
    regex = '''gho_[0-9a-zA-Z]{36}'''
    tags = ["key", "Github"]
```

### Github App Token
```
[[rules]]
    description = "Github App Token"
    regex = '''(ghu|ghs)_[0-9a-zA-Z]{36}'''
    tags = ["key", "Github"]
```

### Github Refresh Token
```
[[rules]]
    description = "Github Refresh Token"
    regex = '''ghr_[0-9a-zA-Z]{76}'''
    tags = ["key", "Github"]
```

## Gitlab Key
```
[[rules]]
	description = "Gitlab Key"
	regex = '''privateToken|private-token'''
	tags = ["keys", "Gitlab"]
```

## Google

### Google API key
```
[[rules]]
	description = "Google API key"
	regex = '''AIza[0-9A-Za-z\\-_]{35}'''
	tags = ["key", "Google"]
```

### Google Cloud Platform API key
```
[[rules]]
description = "Google Cloud Platform API key"
regex = '''(?i)(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0-9a-z\\-_]{35}]['\"]'''
tags = ["key", "Google", "GCP"]
```

### Google OAuth
```
[[rules]]
description = "Google OAuth"
regex = '''(?i)(google|gcp|auth)(.{0,20})?['"][0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com['"]'''
tags = ["key", "Google", "OAuth"]
```

### Google OAuth access token
```
[[rules]]
description = "Google OAuth access token"
regex = '''ya29\.[0-9A-Za-z\-_]+'''
tags = ["key", "Google", "OAuth"]
```

### Google (GCP) Service Account
```
[[rules]]
    description = "Google (GCP) Service Account"
    regex = '''"type": "service_account"'''
    tags = ["key", "Google"]
```

## Heroku API key
```
[[rules]]
	description = "Heroku API key"
	regex = '''(?i)heroku(.{0,20})?['"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"]'''
	tags = ["key", "Heroku"]
```

## LinkedIn

### LinkedIn Client ID
```
[[rules]]
	description = "LinkedIn Client ID"
	regex = '''(?i)linkedin(.{0,20})?(?-i)['\"][0-9a-z]{12}['\"]'''
	tags = ["client", "LinkedIn"]
```

### LinkedIn Secret Key
```
[[rules]]
	description = "LinkedIn Secret Key"
	regex = '''(?i)linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]'''
	tags = ["secret", "LinkedIn"]
```

## MailChimp

### MailChimp API key
```
[[rules]]
	description = "MailChimp API key"
	regex = '''(?i)(mailchimp|mc)(.{0,20})?['"][0-9a-f]{32}-us[0-9]{1,2}['"]'''
	tags = ["key", "Mailchimp"]
```

### MailChimp API key bis
```
[[rules]]
	description = "MailChimp API key bis"
	regex = '''(?i)(mailchimp|mc)(.{0,20})?['"][0-9a-f]{32}-us[0-9]{1,2}['"]'''
	tags = ["key", "Mailchimp"]
```

### Mailgun API key
```
[[rules]]
description = "Mailgun API key"
regex = '''(?i)(mailgun|mg)(.{0,20})?['"][0-9a-z]{32}['"]'''
tags = ["key", "Mailgun"]
```

## Password in URL
```
[[rules]]
description = "Password in URL"
regex = '''[a-zA-Z]{3,10}:\/\/[^\/\s:@]{3,20}:[^\/\s:@]{3,20}@.{1,100}\/?.?'''
tags = ["key", "URL", "generic"]
```

## PayPal Braintree access token
```
[[rules]]
	description = "PayPal Braintree access token"
	regex = '''access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'''
	tags = ["key", "Paypal"]
```
## PGB
```
[[rules]]
description = "PGP"
regex = '''-----BEGIN PGP PRIVATE KEY BLOCK-----'''
tags = ["key", "PGP"]
```

## Picatic API key
```
[[rules]]
	description = "Picatic API key"
	regex = '''sk_live_[0-9a-z]{32}'''
	tags = ["key", "Picatic"]
```

## PKCS8
```
[[rules]]
description = "PKCS8"
regex = '''-----BEGIN PRIVATE KEY-----'''
tags = ["key", "PKCS8"]
```

## Port
```
[[rules]]
  description = "Port"
  regex = '''(?i)port(.{0,4})?[0-9]{1,10}'''
  [rules.allowlist]
  	regexes = ['''(?i)port ''']
  	description = "ignore export "
```

## Public Key
```
[[rules]]
	description = "Public Key"
	regex = '''ssh-rsa'''
	tags = ["keys", "public key"]
```

## PyPI upload token
```
[[rules]]
    description = "PyPI upload token"
    regex = '''pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,1000}'''
    tags = ["key", "pypi"]
```

## RSA
```
[[rules]]
description = "RSA"
regex = '''-----BEGIN RSA PRIVATE KEY-----'''
tags = ["key", "RSA"]
```

## SendGrid API Key
```
[[rules]]
	description = "SendGrid API Key"
	regex = '''SG\.[\w_]{16,32}\.[\w_]{16,64}'''
	tags = ["key", "SendGrid"]
```

## Shopify

### Shopify shared secret
```
[[rules]]
    description = "Shopify shared secret"
    regex = '''shpss_[a-fA-F0-9]{32}'''
    tags = ["key", "Shopify"]
```

### Shopify access token
```
[[rules]]
    description = "Shopify access token"
    regex = '''shpat_[a-fA-F0-9]{32}'''
    tags = ["key", "Shopify"]
```

### Shopify custom app access token
```
[[rules]]
    description = "Shopify custom app access token"
    regex = '''shpca_[a-fA-F0-9]{32}'''
    tags = ["key", "Shopify"]
```

### Shopify private app access token
```
[[rules]]
    description = "Shopify private app access token"
    regex = '''shppa_[a-fA-F0-9]{32}'''
    tags = ["key", "Shopify"]
```

## Slack

### Slack
```
[[rules]]
	description = "Slack"
	regex = '''xox[baprs]-([0-9a-zA-Z]{10,48})?'''
	tags = ["key", "Slack"]
```

detected:
`SLACK_API_KEY: xoxb-8825133122-0721161319009-2cmV8RhmMaFzb7NyFjXZNfgO`

### Slack Webhook
```
[[rules]]
	description = "Slack Webhook"
	regex = '''https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}'''
	tags = ["key", "slack"]
```

## Square

### Square access token
```
[[rules]]
	description = "Square access token"
	regex = '''sq0atp-[0-9A-Za-z\-_]{22}'''
	tags = ["key", "square"]
```

### Square OAuth secret
```
[[rules]]
	description = "Square OAuth secret"
	regex = '''sq0csp-[0-9A-Za-z\\-_]{43}'''
	tags = ["key", "square"]
```

## SSH
```
[[rules]]
description = "SSH"
regex = '''-----BEGIN OPENSSH PRIVATE KEY-----'''
tags = ["key", "SSH"]
```

## Stripe API key
```
[[rules]]
	description = "Stripe API key"
	regex = '''(?i)stripe(.{0,20})?['\"][sk|rk]_live_[0-9a-zA-Z]{24}'''
	tags = ["key", "Stripe"]
```

## system Var

### Env Var
```
[[rules]]
  description = "Env Var"
  regex = '''(?i)(apikey|secret|key|api|password|pass|pw|host)=[0-9a-zA-Z-_.{}]{4,120}'''
```
detected:
`OPSGENIE_API_KEY_URL: https://api.opsgenie.com/v1/json/cloudwatch?apiKey=182663ax-3ccb-20c3-1097-3ol15d0wfu45`

### Potential bash var
```
[[rules]]
  description = "Potential bash var"
  regex='''(?i)(=)([0-9a-zA-Z-_!{}=]{4,120})'''
  tags = ["key", "bash", "API", "generic"]
  [[rules.Entropies]]
    Min = "3.5"
    Max = "4.5"
    Group = "1"
```

## Twilio API key
```
[[rules]]
	description = "Twilio API key"
	regex = '''(?i)twilio(.{0,20})?['\"][0-9a-f]{32}['\"]'''
	tags = ["key", "twilio"]
```

## Twitter

### Twitter Secret Key
```
[[rules]]
	description = "Twitter Secret Key"
	regex = '''(?i)twitter(.{0,20})?['\"][0-9a-z]{35,44}['\"]'''
	tags = ["key", "Twitter"]
```

### Twitter Client ID
```
[[rules]]
	description = "Twitter Client ID"
	regex = '''(?i)twitter(.{0,20})?['\"][0-9a-z]{18,25}['\"]'''
	tags = ["client", "Twitter"]
```

## Generic

### Generic API key
```
[[rules]]
description = "Generic API key"
regex = '''(?i)(api_key|apikey)(.{0,20})?['|"][0-9a-zA-Z]{32,45}['|"]'''
tags = ["key", "API", "generic"]
```

### Generic Credential
```
[[rules]]
  description = "Generic Credential"
  regex = '''(?i)(dbpasswd|dbuser|dbname|dbhost|api_key|apikey|secret|key|api|password|user|guid|hostname|pw|auth)(.{0,20})?['|"]([0-9a-zA-Z-_\/+!{}/=]{4,120})['|"]'''
  tags = ["key", "API", "generic"]
  # ignore leaks with specific identifiers like slack and aws
  [rules.allowlist]
    description = "ignore slack, mailchimp, aws"
    regexes = [
      '''xox[baprs]-([0-9a-zA-Z]{10,48})''',
    	'''(?i)(.{0,20})?['"][0-9a-f]{32}-us[0-9]{1,2}['"]''',
      '''(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'''
    ]
```

### Generic Secret
```
[[rules]]
description = "Generic Secret"
regex = '''(?i)secret(.{0,20})?['|"][0-9a-zA-Z]{32,45}['|"]'''
tags = ["key", "Secret", "generic"]
```

## WP-Config
```
[[rules]]
  description = "WP-Config"
  regex='''define(.{0,20})?(DB_CHARSET|NONCE_SALT|LOGGED_IN_SALT|AUTH_SALT|NONCE_KEY|DB_HOST|DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|DB_NAME|DB_USER)(.{0,20})?['|"].{10,120}['|"]'''
  tags = ["key", "API", "generic"]
```

# GitLeaks Azure rules found

## CSCAN0210: GitCredential
```
[[rules]]
	description = "CSCAN0210: GitCredential"
	regex = '''https?://.+:.+@.*'''
	file = '''\.gitCredentials$'''
```

## CSCAN0010: KeyStoreFile
```
[[rules]]
	description = "CSCAN0010: KeyStoreFile"
	regex = '''.'''
	file = '''\.keystore$'''
```

## CSCAN0020: Base64EncodedCertificateInCode
```
[[rules]]
	description = "CSCAN0020: Base64EncodedCertificateInCode"
	regex = '''['">;=]MII[a-z0-9/+]{200}'''
	file = '''\.(?:cs|ini|json|ps1|publishsettings|template|trd|ts|xml)$'''
```

## CSCAN0020: Base64EncodedCertificateInFile
```
[[rules]]
	description = "CSCAN0020: Base64EncodedCertificateInFile"
	regex = '''MII[A-Za-z0-9/+]{60}'''
	file = '''\.(?:cert|cer)$'''
```

## CSCAN0030: PublishSettings
```
[[rules]]
	description = "CSCAN0030: PublishSettings"
	regex = '''userPWD="[a-zA-Z0-9\+\/]{60}"'''
	file = '''(?i)(publishsettings|\.pubxml$)'''
	[[rules.whitelist]]
		regex = '''Credentials?Type|ConnectionStringKey|notasecret|PartitionKey|notreal|insertkey|LookupKey|IgnoreKeys|SecretsService|SecretsTenantId|(?:Password|pwd|secret|credentials?)(?:Key|Location)|KeyManager'''
	[[rules.whitelist]]
		regex = '''(?:_AppKey"|(?:(?:credential|password|token)s?|(?:Account|access)Key=)"[\s\r?\n]*/|Username"|\.dll|(?:Secret|Token|Key|Credential)s?(?:Encryption|From|(?:Signing)?Certificate|Options|Thumbprint|Contacts|String|UserId)|Key(1;value1|word|s?Path|Index|Id|Store|WillDoWithoutValidation|:NamePattern|Name"|Ref")|(Secret|Credential)s?(Name|Path)"|(StrongName|Chaos\s?Mon|Redis|Registry|Registery|User|Insights?|Instrumentation|Match\()Key|(Certificate|cert)(Issuer|Subject)|rollingdate|skuId|HKEY_|AddServicePrincipalCredentials|Password Resets|SecretStore|(0|x|\*){8,})'''
```

## CSCAN0060: PemFile 1
```
[[rules]]
	description = "CSCAN0060: PemFile 1"
	file = '''\.pem$'''
	regex = '''-{5}BEGIN(?: (?:[dr]sa|ec|openssh))? PRIVATE KEY-{5}'''
```

## CSCAN0091: AspNetMachineKeyInConfig 1
```
[[rules]]
	description = "CSCAN0091: AspNetMachineKeyInConfig 1"
	file = '''\.(?:xml|pubxml|definitions|ps1|wadcfgx|ccf|config|cscfg|json|js|txt|cpp|sql|dtsx|md|java|FF|template|settings|ini|BF|ste|isml|test|ts|resx|Azure|sample|backup|rd|hpp|psm1|cshtml|htm|bat|waz|yml|Beta|py|sh|m|php|xaml|keys|cmd|rds|loadtest|properties)$|hubot'''
	regex = '''<machineKey[^>]+(?:decryptionKey\s*\=\s*"[a-fA-F0-9]{48,}|validationKey\s*\=\s*"[a-fA-F0-9]{48,})[^>]+>'''
	[[rules.whitelist]]
		regex = '''Credentials?Type|ConnectionStringKey|notasecret|PartitionKey|notreal|insertkey|LookupKey|IgnoreKeys|SecretsService|SecretsTenantId|(?:Password|pwd|secret|credentials?)(?:Key|Location)|KeyManager'''
	[[rules.whitelist]]
		regex = '''(?:_AppKey"|(?:(?:credential|password|token)s?|(?:Account|access)Key=)"[\s\r?\n]*/|Username"|\.dll|(?:Secret|Token|Key|Credential)s?(?:Encryption|From|(?:Signing)?Certificate|Options|Thumbprint|Contacts|String|UserId)|Key(1;value1|word|s?Path|Index|Id|Store|WillDoWithoutValidation|:NamePattern|Name"|Ref")|(Secret|Credential)s?(Name|Path)"|(StrongName|Chaos\s?Mon|Redis|Registry|Registery|User|Insights?|Instrumentation|Match\()Key|(Certificate|cert)(Issuer|Subject)|rollingdate|skuId|HKEY_|AddServicePrincipalCredentials|Password Resets|SecretStore|(0|x|\*){8,})'''
```

## CSCAN0091: AspNetMachineKeyInConfig 2
```
[[rules]]
	description = "CSCAN0091: AspNetMachineKeyInConfig 2"
	file = '''\.(?:xml|pubxml|definitions|ps1|wadcfgx|ccf|config|cscfg|json|js|txt|cpp|sql|dtsx|md|java|FF|template|settings|ini|BF|ste|isml|test|ts|resx|Azure|sample|backup|rd|hpp|psm1|cshtml|htm|bat|waz|yml|Beta|py|sh|m|php|xaml|keys|cmd|rds|loadtest|properties)$|hubot'''
	regex = '''(?:decryptionKey|validationKey)="[a-zA-Z0-9]+"'''
	[[rules.whitelist]]
		regex = '''Credentials?Type|ConnectionStringKey|notasecret|PartitionKey|notreal|insertkey|LookupKey|IgnoreKeys|SecretsService|SecretsTenantId|(?:Password|pwd|secret|credentials?)(?:Key|Location)|KeyManager'''
	[[rules.whitelist]]
		regex = '''(?:_AppKey"|(?:(?:credential|password|token)s?|(?:Account|access)Key=)"[\s\r?\n]*/|Username"|\.dll|(?:Secret|Token|Key|Credential)s?(?:Encryption|From|(?:Signing)?Certificate|Options|Thumbprint|Contacts|String|UserId)|Key(1;value1|word|s?Path|Index|Id|Store|WillDoWithoutValidation|:NamePattern|Name"|Ref")|(Secret|Credential)s?(Name|Path)"|(StrongName|Chaos\s?Mon|Redis|Registry|Registery|User|Insights?|Instrumentation|Match\()Key|(Certificate|cert)(Issuer|Subject)|rollingdate|skuId|HKEY_|AddServicePrincipalCredentials|Password Resets|SecretStore|(0|x|\*){8,})'''
```

## CSCAN0092: SqlConnectionStringInConfig 1
```
[[rules]]
	description = "CSCAN0092: SqlConnectionStringInConfig 1"
	file = '''\.(?:xml|pubxml|definitions|ps1|wadcfgx|ccf|config|cscfg|json|js|txt|cpp|sql|dtsx|md|java|FF|template|settings|ini|BF|ste|isml|test|ts|resx|Azure|sample|backup|rd|hpp|psm1|cshtml|htm|bat|waz|yml|Beta|py|sh|m|php|xaml|keys|cmd|rds|loadtest|properties)$|hubot'''
	regex = '''(?i)(?:connection[sS]tring|connString)[^=]*=["'][^"']*[pP]assword\s*=\s*[^\s;][^"']*(?:'|")'''
	[[rules.whitelist]]
		regex = '''Credentials?Type|ConnectionStringKey|notasecret|PartitionKey|notreal|insertkey|LookupKey|IgnoreKeys|SecretsService|SecretsTenantId|(?:Password|pwd|secret|credentials?)(?:Key|Location)|KeyManager'''
```

## CSCAN0092: SqlConnectionStringInConfig 2 / CSCAN0043 SqlConnectionStringInCode
```
[[rules]]
	description = "CSCAN0092: SqlConnectionStringInConfig 2 / CSCAN0043 SqlConnectionStringInCode"
	file = '''\.(?:xml|pubxml|definitions|ps1|wadcfgx|ccf|config|cscfg|json|js|txt|cpp|sql|dtsx|md|java|FF|template|settings|ini|BF|ste|isml|test|ts|resx|Azure|sample|backup|rd|hpp|psm1|cshtml|htm|bat|waz|yml|Beta|py|sh|m|php|xaml|keys|cmd|rds|loadtest|properties|policy_and_key\.hpp|AccountConfig\.h)$|hubot'''
	regex = '''(?i)(?:User ID|uid|UserId).*(?:Password|[^a-z]pwd)=[^'\$%<@'";\[\{][^;/"]{4,128}(?:;|")'''
	[[rules.whitelist]]
		regex = '''Credentials?Type|ConnectionStringKey|notasecret|PartitionKey|notreal|insertkey|LookupKey|IgnoreKeys|SecretsService|SecretsTenantId|(?:Password|pwd|secret|credentials?)(?:Key|Location)|KeyManager'''
	[[rules.whitelist]]
		regex = '''(?:prefix <<|guestaccesstoken|skiptoken|cookie|tsm|fake|example|badlyFormatted|Invalid|sha512|sha256|"input"|ENCRYPTED|"EncodedRequestUri"|looks like|myStorageAccountName|(?:0|x|\*){8,})'''
```

## CSCAN0093: StorageAccountKeyInConfig 1
```
[[rules]]
	description = "CSCAN0093: StorageAccountKeyInConfig 1"
	file = '''\.(?:xml|pubxml|definitions|ps1|wadcfgx|ccf|config|cscfg|json|js|txt|cpp|sql|dtsx|md|java|FF|template|settings|ini|BF|ste|isml|test|ts|resx|Azure|sample|backup|rd|hpp|psm1|cshtml|htm|bat|waz|yml|Beta|py|sh|m|php|xaml|keys|cmd|rds|loadtest|properties)$|hubot'''
	regex = '''[^a-z0-9/\+\._\-\$,\\][a-z0-9/+]{86}=='''
```

## CSCAN0041: StorageAccountKeyInCode 1
```
[[rules]]
	description = "CSCAN0041: StorageAccountKeyInCode 1"
	file = '''(?:\.(?:cs|js|ts|cpp)|policy_and_key\.hpp|AccountConfig\.h)$'''
	regex = '''[^a-z0-9/\+\._\-\$,\\][a-z0-9/+]{86}=='''
```

## CSCAN0094: SharedAccessSignatureInCode 1
```
[[rules]]
	description = "CSCAN0094: SharedAccessSignatureInCode 1"
	file = '''(?:\.(?:cs|js|ts|cpp)|policy_and_key\.hpp|AccountConfig\.h)$'''
	regex = '''[^a-z0-9/\+\._\-\$,\\][a-z0-9/+]{43}=[^{@]'''
```

## CSCAN0094: SharedAccessSignatureInCode 2
```
[[rules]]
	description = "CSCAN0094: SharedAccessSignatureInCode 2"
	file = '''(?:\.(?:cs|js|ts|cpp)|policy_and_key\.hpp|AccountConfig\.h)$'''
	regex = '''[^a-z0-9/\+\._\-\$,\\][a-z0-9%]{43,53}%3d[^a-z0-9%]'''
```

## CSCAN0094: SharedAccessSignatureInConfig 1
```
[[rules]]
	description = "CSCAN0094: SharedAccessSignatureInConfig 1"
	file = '''\.(?:xml|pubxml|definitions|ps1|wadcfgx|ccf|config|cscfg|json|js|txt|cpp|sql|dtsx|md|java|FF|template|settings|ini|BF|ste|isml|test|ts|resx|Azure|sample|backup|rd|hpp|psm1|cshtml|htm|bat|waz|yml|Beta|py|sh|m|php|xaml|keys|cmd|rds|loadtest|properties)$|hubot'''
	regex = '''[^a-z0-9/\+\._\-\$,\\][a-z0-9/+]{43}=[^{@]'''
```

## CSCAN0094: SharedAccessSignatureInConfig 2
```
[[rules]]
	description = "CSCAN0094: SharedAccessSignatureInConfig 2"
	file = '''\.(?:xml|pubxml|definitions|ps1|wadcfgx|ccf|config|cscfg|json|js|txt|cpp|sql|dtsx|md|java|FF|template|settings|ini|BF|ste|isml|test|ts|resx|Azure|sample|backup|rd|hpp|psm1|cshtml|htm|bat|waz|yml|Beta|py|sh|m|php|xaml|keys|cmd|rds|loadtest|properties)$|hubot'''
	regex = '''[^a-z0-9/\+\._\-\$,\\][a-z0-9%]{43,53}%3d[^a-z0-9%]'''
```

## CSCAN0095: GeneralSecretInConfig 1
```
[[rules]]
	description = "CSCAN0095: GeneralSecretInConfig 1"
	file = '''\.(?:config|cscfg|json|js|txt|cpp|sql|dtsx|md|java|FF|template|settings|ini|BF|ste|isml|test|ts|resx|Azure|sample|backup|rd|hpp|psm1|cshtml|htm|bat|waz|yml|Beta|py|sh|m|php|xaml|keys|cmd|rds|loadtest|properties)$|hubot'''
	regex = '''<add\skey="[^"]+(?:key(?:s|[0-9])?|credentials?|secret(?:s|[0-9])?|password|token|KeyPrimary|KeySecondary|KeyOrSas|KeyEncrypted)"\s*value\s*="[^"]+"[^>]*/>'''
	[[rules.whitelist]]
		regex = '''key\s*=\s*"[^"]*AppKey[^"]*"\s+value\s*=\s*"[a-z]+"'''
	[[rules.whitelist]]
		regex = '''value\s*=\s*"(?:[a-z]+(?: [a-z]+)+"|_+[a-z]+_+"|[a-z]+-[a-z]+-[a-z]+["-]|[a-z]+-[a-z]+"|[a-z]+\\[a-z]+"|\d+"|[^"]*ConnectionString")'''
	[[rules.whitelist]]
		regex = '''Credentials?Type|ConnectionStringKey|notasecret|PartitionKey|notreal|insertkey|LookupKey|IgnoreKeys|SecretsService|SecretsTenantId|(?:Password|pwd|secret|credentials?)(?:Key|Location)|KeyManager'''
	[[rules.whitelist]]
		regex = '''value="(?:true|false|@\(api|ssh\-rsa 2048|invalid|to be|a shared secret|secreturi|clientsecret|Overr?idden by|someValue|SOME\-SIGNING\-KEY|TokenBroker|UNKNOWN|Client Secret of|Junk Credentials|Default\-|__BOOTSTRAPKEY_|CacheSecret|CatalogCert|CosmosCredentials|DeleteServiceCert|EmailCredentials|MetricsConnection|SangamCredentials|SubscriptionConnection|Enter_your_|My_Issuer|ScaleUnitXstoreSharedKey|private_powerapps|TestSecret|foo_|bar_|temp_|__WinfabricTestInfra|configured|SecretFor|Test|XSTORE_KEY|ServiceBusDiagnosticXstoreSharedKey|BoxApplicationKey|googleapps)'''
	[[rules.whitelist]]
		regex = '''(?:_AppKey"|(?:(?:credential|password|token)s?|(?:Account|access)Key=)"[\s\r?\n]*/|Username"|\.dll|(?:Secret|Token|Key|Credential)s?(?:Encryption|From|(?:Signing)?Certificate|Options|Thumbprint|Contacts|String|UserId)|Key(1;value1|word|s?Path|Index|Id|Store|WillDoWithoutValidation|:NamePattern|Name"|Ref")|(Secret|Credential)s?(Name|Path)"|(StrongName|Chaos\s?Mon|Redis|Registry|Registery|User|Insights?|Instrumentation|Match\()Key|(Certificate|cert)(Issuer|Subject)|rollingdate|skuId|HKEY_|AddServicePrincipalCredentials|Password Resets|SecretStore|(0|x|\*){8,})'''
	[[rules.whitelist]]
		regex = '''AccountKey\s*=\s*MII[a-z0-9/+]{43,}={0,2}'''
```

## CSCAN0095: GeneralSecretInConfig 2
```
[[rules]]
	description = "CSCAN0095: GeneralSecretInConfig 2"
	file = '''\.(?:config|cscfg|json|js|txt|cpp|sql|dtsx|md|java|FF|template|settings|ini|BF|ste|isml|test|ts|resx|Azure|sample|backup|rd|hpp|psm1|cshtml|htm|bat|waz|yml|Beta|py|sh|m|php|xaml|keys|cmd|rds|loadtest|properties)$|hubot'''
	regex = '''<add\skey="[^"]+"\s*value="[^"]*EncryptedSecret:[^"]+"\s*/>'''
	[[rules.whitelist]]
		regex = '''key\s*=\s*"[^"]*AppKey[^"]*"\s+value\s*=\s*"[a-z]+"'''
	[[rules.whitelist]]
		regex = '''value\s*=\s*"(?:[a-z]+(?: [a-z]+)+"|_+[a-z]+_+"|[a-z]+-[a-z]+-[a-z]+["-]|[a-z]+-[a-z]+"|[a-z]+\\[a-z]+"|\d+"|[^"]*ConnectionString")'''
	[[rules.whitelist]]
		regex = '''Credentials?Type|ConnectionStringKey|notasecret|PartitionKey|notreal|insertkey|LookupKey|IgnoreKeys|SecretsService|SecretsTenantId|(?:Password|pwd|secret|credentials?)(?:Key|Location)|KeyManager'''
	[[rules.whitelist]]
		regex = '''value="(?:true|false|@\(api|ssh\-rsa 2048|invalid|to be|a shared secret|secreturi|clientsecret|Overr?idden by|someValue|SOME\-SIGNING\-KEY|TokenBroker|UNKNOWN|Client Secret of|Junk Credentials|Default\-|__BOOTSTRAPKEY_|CacheSecret|CatalogCert|CosmosCredentials|DeleteServiceCert|EmailCredentials|MetricsConnection|SangamCredentials|SubscriptionConnection|Enter_your_|My_Issuer|ScaleUnitXstoreSharedKey|private_powerapps|TestSecret|foo_|bar_|temp_|__WinfabricTestInfra|configured|SecretFor|Test|XSTORE_KEY|ServiceBusDiagnosticXstoreSharedKey|BoxApplicationKey|googleapps)'''
	[[rules.whitelist]]
		regex = '''(?:_AppKey"|(?:(?:credential|password|token)s?|(?:Account|access)Key=)"[\s\r?\n]*/|Username"|\.dll|(?:Secret|Token|Key|Credential)s?(?:Encryption|From|(?:Signing)?Certificate|Options|Thumbprint|Contacts|String|UserId)|Key(1;value1|word|s?Path|Index|Id|Store|WillDoWithoutValidation|:NamePattern|Name"|Ref")|(Secret|Credential)s?(Name|Path)"|(StrongName|Chaos\s?Mon|Redis|Registry|Registery|User|Insights?|Instrumentation|Match\()Key|(Certificate|cert)(Issuer|Subject)|rollingdate|skuId|HKEY_|AddServicePrincipalCredentials|Password Resets|SecretStore|(0|x|\*){8,})'''
	[[rules.whitelist]]
		regex = '''AccountKey\s*=\s*MII[a-z0-9/+]{43,}={0,2}'''
```

## CSCAN0095: GeneralSecretInConfig 3
```
[[rules]]
	description = "CSCAN0095: GeneralSecretInConfig 3"
	file = '''\.(?:config|cscfg|json|js|txt|cpp|sql|dtsx|md|java|FF|template|settings|ini|BF|ste|isml|test|ts|resx|Azure|sample|backup|rd|hpp|psm1|cshtml|htm|bat|waz|yml|Beta|py|sh|m|php|xaml|keys|cmd|rds|loadtest|properties)$|hubot'''
	regex = '''<Credential\sname="[^"]*(?:key(?:s|[0-9])?|credentials?|secret(?:s|[0-9])?|password|token|KeyPrimary|KeySecondary|KeyOrSas|KeyEncrypted)"(\s*value\s*="[^"]+".*?/>|[^>]*>.*?</Credential>)'''
	[[rules.whitelist]]
		regex = '''key\s*=\s*"[^"]*AppKey[^"]*"\s+value\s*=\s*"[a-z]+"'''
	[[rules.whitelist]]
		regex = '''value\s*=\s*"(?:[a-z]+(?: [a-z]+)+"|_+[a-z]+_+"|[a-z]+-[a-z]+-[a-z]+["-]|[a-z]+-[a-z]+"|[a-z]+\\[a-z]+"|\d+"|[^"]*ConnectionString")'''
	[[rules.whitelist]]
		regex = '''Credentials?Type|ConnectionStringKey|notasecret|PartitionKey|notreal|insertkey|LookupKey|IgnoreKeys|SecretsService|SecretsTenantId|(?:Password|pwd|secret|credentials?)(?:Key|Location)|KeyManager'''
	[[rules.whitelist]]
		regex = '''value="(?:true|false|@\(api|ssh\-rsa 2048|invalid|to be|a shared secret|secreturi|clientsecret|Overr?idden by|someValue|SOME\-SIGNING\-KEY|TokenBroker|UNKNOWN|Client Secret of|Junk Credentials|Default\-|__BOOTSTRAPKEY_|CacheSecret|CatalogCert|CosmosCredentials|DeleteServiceCert|EmailCredentials|MetricsConnection|SangamCredentials|SubscriptionConnection|Enter_your_|My_Issuer|ScaleUnitXstoreSharedKey|private_powerapps|TestSecret|foo_|bar_|temp_|__WinfabricTestInfra|configured|SecretFor|Test|XSTORE_KEY|ServiceBusDiagnosticXstoreSharedKey|BoxApplicationKey|googleapps)'''
	[[rules.whitelist]]
		regex = '''(?:_AppKey"|(?:(?:credential|password|token)s?|(?:Account|access)Key=)"[\s\r?\n]*/|Username"|\.dll|(?:Secret|Token|Key|Credential)s?(?:Encryption|From|(?:Signing)?Certificate|Options|Thumbprint|Contacts|String|UserId)|Key(1;value1|word|s?Path|Index|Id|Store|WillDoWithoutValidation|:NamePattern|Name"|Ref")|(Secret|Credential)s?(Name|Path)"|(StrongName|Chaos\s?Mon|Redis|Registry|Registery|User|Insights?|Instrumentation|Match\()Key|(Certificate|cert)(Issuer|Subject)|rollingdate|skuId|HKEY_|AddServicePrincipalCredentials|Password Resets|SecretStore|(0|x|\*){8,})'''
	[[rules.whitelist]]
		regex = '''AccountKey\s*=\s*MII[a-z0-9/+]{43,}={0,2}'''
```

## CSCAN0095: GeneralSecretInConfig 4
```
[[rules]]
	description = "CSCAN0095: GeneralSecretInConfig 4"
	file = '''\.(?:config|cscfg|json|js|txt|cpp|sql|dtsx|md|java|FF|template|settings|ini|BF|ste|isml|test|ts|resx|Azure|sample|backup|rd|hpp|psm1|cshtml|htm|bat|waz|yml|Beta|py|sh|m|php|xaml|keys|cmd|rds|loadtest|properties)$|hubot'''
	regex = '''<setting\sname="[^"]*Password".*[\r?\n]*\s*<value>.+</value>'''
	[[rules.whitelist]]
		regex = '''key\s*=\s*"[^"]*AppKey[^"]*"\s+value\s*=\s*"[a-z]+"'''
	[[rules.whitelist]]
		regex = '''value\s*=\s*"(?:[a-z]+(?: [a-z]+)+"|_+[a-z]+_+"|[a-z]+-[a-z]+-[a-z]+["-]|[a-z]+-[a-z]+"|[a-z]+\\[a-z]+"|\d+"|[^"]*ConnectionString")'''
	[[rules.whitelist]]
		regex = '''Credentials?Type|ConnectionStringKey|notasecret|PartitionKey|notreal|insertkey|LookupKey|IgnoreKeys|SecretsService|SecretsTenantId|(?:Password|pwd|secret|credentials?)(?:Key|Location)|KeyManager'''
	[[rules.whitelist]]
		regex = '''(?:_AppKey"|(?:(?:credential|password|token)s?|(?:Account|access)Key=)"[\s\r?\n]*/|Username"|\.dll|(?:Secret|Token|Key|Credential)s?(?:Encryption|From|(?:Signing)?Certificate|Options|Thumbprint|Contacts|String|UserId)|Key(1;value1|word|s?Path|Index|Id|Store|WillDoWithoutValidation|:NamePattern|Name"|Ref")|(Secret|Credential)s?(Name|Path)"|(StrongName|Chaos\s?Mon|Redis|Registry|Registery|User|Insights?|Instrumentation|Match\()Key|(Certificate|cert)(Issuer|Subject)|rollingdate|skuId|HKEY_|AddServicePrincipalCredentials|Password Resets|SecretStore|(0|x|\*){8,})'''
	[[rules.whitelist]]
		regex = '''value="(?:true|false|@\(api|ssh\-rsa 2048|invalid|to be|a shared secret|secreturi|clientsecret|Overr?idden by|someValue|SOME\-SIGNING\-KEY|TokenBroker|UNKNOWN|Client Secret of|Junk Credentials|Default\-|__BOOTSTRAPKEY_|CacheSecret|CatalogCert|CosmosCredentials|DeleteServiceCert|EmailCredentials|MetricsConnection|SangamCredentials|SubscriptionConnection|Enter_your_|My_Issuer|ScaleUnitXstoreSharedKey|private_powerapps|TestSecret|foo_|bar_|temp_|__WinfabricTestInfra|configured|SecretFor|Test|XSTORE_KEY|ServiceBusDiagnosticXstoreSharedKey|BoxApplicationKey|googleapps)'''
	[[rules.whitelist]]
		regex = '''AccountKey\s*=\s*MII[a-z0-9/+]{43,}={0,2}'''
```

## CSCAN0110: ScriptPassword 1
```
[[rules]]
	description = "CSCAN0110: ScriptPassword 1"
	file = '''(?:\.cmd|\.ps|\.ps1|\.psm1)$'''
	regex = '''\s-Password\s+(?:"[^"]*"|'[^']*')'''
```

## CSCAN0110: ScriptPassword 2
```
[[rules]]
	description = "CSCAN0110: ScriptPassword 2"
	file = '''(?:\.cmd|\.ps|\.ps1|\.psm1)$'''
	regex = '''\s-Password\s+[^$\(\)\[\{<\-\r?\n]+\s*(?:\r?\n|\-)'''
```

## CSCAN0120: ExternalApiSecret
```
[[rules]]
	description = "CSCAN0120: ExternalApiSecret"
	file = '''\.cs$|\.cpp$|\.c$'''
	regex = '''(private\sconst\sstring\sAccessTokenSecret|private\sconst\sstring\saccessToken|private\sconst\sstring\sconsumerSecret|private\sconst\sstring\sconsumerKey|pageAccessToken|private\sstring\stwilioAccountSid|private\sstring\stwilioAuthToken)\s=\s".*";'''
```

## CSCAN0220: DefaultPasswordContexts 1
```
[[rules]]
	description = "CSCAN0220: DefaultPasswordContexts 1"
	file = '''\.(?:ps1|psm1|)$'''
	regex = '''ConvertTo-SecureString(?:\s*-String)?\s*"[^"\r?\n]+"'''
	[[rules.whitelist]]
		regex = '''Credentials?Type|ConnectionStringKey|notasecret|PartitionKey|notreal|insertkey|LookupKey|IgnoreKeys|SecretsService|SecretsTenantId|(?:Password|pwd|secret|credentials?)(?:Key|Location)|KeyManager'''
	[[rules.whitelist]]
		regex = '''(?:_AppKey"|(?:(?:credential|password|token)s?|(?:Account|access)Key=)"[\s\r?\n]*/|Username"|\.dll|(?:Secret|Token|Key|Credential)s?(?:Encryption|From|(?:Signing)?Certificate|Options|Thumbprint|Contacts|String|UserId)|Key(1;value1|word|s?Path|Index|Id|Store|WillDoWithoutValidation|:NamePattern|Name"|Ref")|(Secret|Credential)s?(Name|Path)"|(StrongName|Chaos\s?Mon|Redis|Registry|Registery|User|Insights?|Instrumentation|Match\()Key|(Certificate|cert)(Issuer|Subject)|rollingdate|skuId|HKEY_|AddServicePrincipalCredentials|Password Resets|SecretStore|(0|x|\*){8,})'''
```

## CSCAN0220: DefaultPasswordContexts 2
```
[[rules]]
	description = "CSCAN0220: DefaultPasswordContexts 2"
	file = '''\.(?:cs|xml|config|json|ts|cfg|txt|ps1|bat|cscfg|publishsettings|cmd|psm1|aspx|asmx|vbs|added_cluster|clean|pubxml|ccf|ini|svd|sql|c|xslt|csv|FF|ExtendedTests|settings|cshtml|template|trd|argfile)$|(config|certificate|publish|UT)\.js$|(commands|user|tests)\.cpp$'''
	regex = '''new\sX509Certificate2\([^()]*,\s*"[^"\r?\n]+"[^)]*\)'''
	[[rules.whitelist]]
		regex = '''Credentials?Type|ConnectionStringKey|notasecret|PartitionKey|notreal|insertkey|LookupKey|IgnoreKeys|SecretsService|SecretsTenantId|(?:Password|pwd|secret|credentials?)(?:Key|Location)|KeyManager'''
	[[rules.whitelist]]
		regex = '''(?:_AppKey"|(?:(?:credential|password|token)s?|(?:Account|access)Key=)"[\s\r?\n]*/|Username"|\.dll|(?:Secret|Token|Key|Credential)s?(?:Encryption|From|(?:Signing)?Certificate|Options|Thumbprint|Contacts|String|UserId)|Key(1;value1|word|s?Path|Index|Id|Store|WillDoWithoutValidation|:NamePattern|Name"|Ref")|(Secret|Credential)s?(Name|Path)"|(StrongName|Chaos\s?Mon|Redis|Registry|Registery|User|Insights?|Instrumentation|Match\()Key|(Certificate|cert)(Issuer|Subject)|rollingdate|skuId|HKEY_|AddServicePrincipalCredentials|Password Resets|SecretStore|(0|x|\*){8,})'''
```

## CSCAN0220: DefaultPasswordContexts 3
```
[[rules]]
	description = "CSCAN0220: DefaultPasswordContexts 3"
	file = '''\.(?:cs|xml|config|json|ts|cfg|txt|ps1|bat|cscfg|publishsettings|cmd|psm1|aspx|asmx|vbs|added_cluster|clean|pubxml|ccf|ini|svd|sql|c|xslt|csv|FF|ExtendedTests|settings|cshtml|template|trd|argfile)$|(config|certificate|publish|UT)\.js$|(commands|user|tests)\.cpp$'''
	regex = '''AdminPassword\s*=\s*"[^"\r?\n]+"'''
	[[rules.whitelist]]
		regex = '''Credentials?Type|ConnectionStringKey|notasecret|PartitionKey|notreal|insertkey|LookupKey|IgnoreKeys|SecretsService|SecretsTenantId|(?:Password|pwd|secret|credentials?)(?:Key|Location)|KeyManager'''
	[[rules.whitelist]]
		regex = '''(?:_AppKey"|(?:(?:credential|password|token)s?|(?:Account|access)Key=)"[\s\r?\n]*/|Username"|\.dll|(?:Secret|Token|Key|Credential)s?(?:Encryption|From|(?:Signing)?Certificate|Options|Thumbprint|Contacts|String|UserId)|Key(1;value1|word|s?Path|Index|Id|Store|WillDoWithoutValidation|:NamePattern|Name"|Ref")|(Secret|Credential)s?(Name|Path)"|(StrongName|Chaos\s?Mon|Redis|Registry|Registery|User|Insights?|Instrumentation|Match\()Key|(Certificate|cert)(Issuer|Subject)|rollingdate|skuId|HKEY_|AddServicePrincipalCredentials|Password Resets|SecretStore|(0|x|\*){8,})'''
```

## CSCAN0220: DefaultPasswordContexts 4
```
[[rules]]
	description = "CSCAN0220: DefaultPasswordContexts 4"
	file = '''\.(?:cs|xml|config|json|ts|cfg|txt|ps1|bat|cscfg|publishsettings|cmd|psm1|aspx|asmx|vbs|added_cluster|clean|pubxml|ccf|ini|svd|sql|c|xslt|csv|FF|ExtendedTests|settings|cshtml|template|trd|argfile)$|(config|certificate|publish|UT)\.js$|(commands|user|tests)\.cpp$'''
	regex = '''(?i)<password>.+</password>'''
	[[rules.whitelist]]
		regex = '''Credentials?Type|ConnectionStringKey|notasecret|PartitionKey|notreal|insertkey|LookupKey|IgnoreKeys|SecretsService|SecretsTenantId|(?:Password|pwd|secret|credentials?)(?:Key|Location)|KeyManager'''
	[[rules.whitelist]]
		regex = '''(?:_AppKey"|(?:(?:credential|password|token)s?|(?:Account|access)Key=)"[\s\r?\n]*/|Username"|\.dll|(?:Secret|Token|Key|Credential)s?(?:Encryption|From|(?:Signing)?Certificate|Options|Thumbprint|Contacts|String|UserId)|Key(1;value1|word|s?Path|Index|Id|Store|WillDoWithoutValidation|:NamePattern|Name"|Ref")|(Secret|Credential)s?(Name|Path)"|(StrongName|Chaos\s?Mon|Redis|Registry|Registery|User|Insights?|Instrumentation|Match\()Key|(Certificate|cert)(Issuer|Subject)|rollingdate|skuId|HKEY_|AddServicePrincipalCredentials|Password Resets|SecretStore|(0|x|\*){8,})'''
```

## CSCAN0220: DefaultPasswordContexts 5
```
[[rules]]
	description = "CSCAN0220: DefaultPasswordContexts 5"
	file = '''\.(?:cs|xml|config|json|ts|cfg|txt|ps1|bat|cscfg|publishsettings|cmd|psm1|aspx|asmx|vbs|added_cluster|clean|pubxml|ccf|ini|svd|sql|c|xslt|csv|FF|ExtendedTests|settings|cshtml|template|trd|argfile)$|(config|certificate|publish|UT)\.js$|(commands|user|tests)\.cpp$'''
	regex = '''ClearTextPassword"?\s*[:=]\s*"[^"\r?\n]+"'''
	[[rules.whitelist]]
		regex = '''Credentials?Type|ConnectionStringKey|notasecret|PartitionKey|notreal|insertkey|LookupKey|IgnoreKeys|SecretsService|SecretsTenantId|(?:Password|pwd|secret|credentials?)(?:Key|Location)|KeyManager'''
	[[rules.whitelist]]
		regex = '''(?:_AppKey"|(?:(?:credential|password|token)s?|(?:Account|access)Key=)"[\s\r?\n]*/|Username"|\.dll|(?:Secret|Token|Key|Credential)s?(?:Encryption|From|(?:Signing)?Certificate|Options|Thumbprint|Contacts|String|UserId)|Key(1;value1|word|s?Path|Index|Id|Store|WillDoWithoutValidation|:NamePattern|Name"|Ref")|(Secret|Credential)s?(Name|Path)"|(StrongName|Chaos\s?Mon|Redis|Registry|Registery|User|Insights?|Instrumentation|Match\()Key|(Certificate|cert)(Issuer|Subject)|rollingdate|skuId|HKEY_|AddServicePrincipalCredentials|Password Resets|SecretStore|(0|x|\*){8,})'''
```

## CSCAN0220: DefaultPasswordContexts 6
```
[[rules]]
	description = "CSCAN0220: DefaultPasswordContexts 6"
	file = '''\.(?:cs|xml|config|json|ts|cfg|txt|ps1|bat|cscfg|publishsettings|cmd|psm1|aspx|asmx|vbs|added_cluster|clean|pubxml|ccf|ini|svd|sql|c|xslt|csv|FF|ExtendedTests|settings|cshtml|template|trd|argfile)$|(config|certificate|publish|UT)\.js$|(commands|user|tests)\.cpp$'''
	regex = '''certutil.*?\-p\s+("[^"%]+"|'[^'%]+'|[^"']\S*\s)'''
	[[rules.whitelist]]
		regex = '''Credentials?Type|ConnectionStringKey|notasecret|PartitionKey|notreal|insertkey|LookupKey|IgnoreKeys|SecretsService|SecretsTenantId|(?:Password|pwd|secret|credentials?)(?:Key|Location)|KeyManager'''
	[[rules.whitelist]]
		regex = '''(?:_AppKey"|(?:(?:credential|password|token)s?|(?:Account|access)Key=)"[\s\r?\n]*/|Username"|\.dll|(?:Secret|Token|Key|Credential)s?(?:Encryption|From|(?:Signing)?Certificate|Options|Thumbprint|Contacts|String|UserId)|Key(1;value1|word|s?Path|Index|Id|Store|WillDoWithoutValidation|:NamePattern|Name"|Ref")|(Secret|Credential)s?(Name|Path)"|(StrongName|Chaos\s?Mon|Redis|Registry|Registery|User|Insights?|Instrumentation|Match\()Key|(Certificate|cert)(Issuer|Subject)|rollingdate|skuId|HKEY_|AddServicePrincipalCredentials|Password Resets|SecretStore|(0|x|\*){8,})'''
```

## CSCAN0220: DefaultPasswordContexts 7
```
[[rules]]
	description = "CSCAN0220: DefaultPasswordContexts 7"
	file = '''\.(?:cs|xml|config|json|ts|cfg|txt|ps1|bat|cscfg|publishsettings|cmd|psm1|aspx|asmx|vbs|added_cluster|clean|pubxml|ccf|ini|svd|sql|c|xslt|csv|FF|ExtendedTests|settings|cshtml|template|trd|argfile)$|(config|certificate|publish|UT)\.js$|(commands|user|tests)\.cpp$'''
	regex = '''password\s*=\s*N?(["][^"\r?\n]{4,}["]|['][^'\r?\n]{4,}['])'''
	[[rules.whitelist]]
		regex = '''Credentials?Type|ConnectionStringKey|notasecret|PartitionKey|notreal|insertkey|LookupKey|IgnoreKeys|SecretsService|SecretsTenantId|(?:Password|pwd|secret|credentials?)(?:Key|Location)|KeyManager'''
	[[rules.whitelist]]
		regex = '''(?:_AppKey"|(?:(?:credential|password|token)s?|(?:Account|access)Key=)"[\s\r?\n]*/|Username"|\.dll|(?:Secret|Token|Key|Credential)s?(?:Encryption|From|(?:Signing)?Certificate|Options|Thumbprint|Contacts|String|UserId)|Key(1;value1|word|s?Path|Index|Id|Store|WillDoWithoutValidation|:NamePattern|Name"|Ref")|(Secret|Credential)s?(Name|Path)"|(StrongName|Chaos\s?Mon|Redis|Registry|Registery|User|Insights?|Instrumentation|Match\()Key|(Certificate|cert)(Issuer|Subject)|rollingdate|skuId|HKEY_|AddServicePrincipalCredentials|Password Resets|SecretStore|(0|x|\*){8,})'''
```

## CSCAN0160: DomainPassword
```
[[rules]]
	description = "CSCAN0160: DomainPassword"
	regex = '''new(?:-object)?\s+System.Net.NetworkCredential\(?:.*?,\s*"[^"]+"'''
	file = '''\.cs$|\.c$|\.cpp$|\.ps1$|\.ps$|\.cmd$|\.bat$|\.log$|\.psd$|\.psm1$'''
	[[rules.whitelist]]
		regex = '''(%1%|\$MIGUSER_PASSWORD|%miguser_pwd%)'''
		description = "ignore placeholders"
```

## CSCAN0240: VstsPersonalAccessToken 1
```
[[rules]]
	description = "CSCAN0240: VstsPersonalAccessToken 1"
	file = '''\.(?:cs|ps1|bat|config|xml|json)$'''
	regex = '''(?i)(?:AccessToken|pat|token).*?[':="][a-z0-9]{52}(?:'|"|\s|[\r?\n]+)'''
```

## CSCAN0240: VstsPersonalAccessToken 2
```
[[rules]]
	description = "CSCAN0240: VstsPersonalAccessToken 2"
	file = '''\.(?:cs|ps1|bat|config|xml|json)$'''
	regex = '''(?i)(?:AccessToken|pat|token).*?[':="][a-z0-9/+]{70}==(?:'|"|\s|[\r?\n]+)'''
```

## CSCAN0250: OAuthToken 1
```
[[rules]]
	description = "CSCAN0250: OAuthToken 1"
	file = '''\.(?:config|js|json|txt|cs|xml|java|py)$'''
	regex = '''eyj[a-z0-9\-_%]+\.eyj[a-z0-9\-_%]+\.[a-z0-9\-_%]+'''
```

## CSCAN0250: OAuthToken 2
```
[[rules]]
	description = "CSCAN0250: OAuthToken 2"
	file = '''\.(?:config|js|json|txt|cs|xml|java|py)$'''
	regex = '''refresh_token["']?\s*[:=]\s*["']?(?:[a-z0-9_]+-)+[a-z0-9_]+["']?'''
```

## CSCAN0260: AnsibleVault
```
[[rules]]
	description = "CSCAN0260: AnsibleVault"
	file = '''\.yml$'''
	regex = '''\$ANSIBLE_VAULT;[0-9]\.[0-9];AES256[\r?\n]+[0-9]+'''
```

## CSCAN0230: SlackToken 1
```
[[rules]]
	description = "CSCAN0230: SlackToken 1"
    regex = '''xoxp-[a-z0-9]+-[a-z0-9]+-[a-z0-9]+-[a-z0-9]+'''
	file = '''\.(?:ps1|psm1|js|json|coffee|xml|js|md|html|py|php|java|ipynb|rb)$|hubot'''
```

## CSCAN0230: SlackToken 2
```
[[rules]]
	description = "CSCAN0230: SlackToken 2"
	regex = '''xoxb-[a-z0-9]+-[a-z0-9]+'''
	file = '''\.(?:ps1|psm1|js|json|coffee|xml|js|md|html|py|php|java|ipynb|rb)$|hubot'''
```
