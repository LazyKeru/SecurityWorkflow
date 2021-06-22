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
	regex = '''https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}'''
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
