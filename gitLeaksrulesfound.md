# GitLeaks rules found

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

## Facebook

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

## Slack

### Slack
```
[[rules]]
	description = "Slack"
	regex = '''xox[baprs]-([0-9a-zA-Z]{10,48})?'''
	tags = ["key", "Slack"]
```

### Slack Webhook
```
[[rules]]
	description = "Slack Webhook"
	regex = '''https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}'''
	tags = ["key", "slack"]
```

## EC
```
[[rules]]
  description = "EC"
  regex = '''-----BEGIN EC PRIVATE KEY-----'''
  tags = ["key", "EC"]
```

## Asymmetric Private Key
```
[[rules]]
	description = "Asymmetric Private Key"
	regex = '''-----BEGIN ((EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY( BLOCK)?-----'''
	tags = ["key", "AsymmetricPrivateKey"]
```

## Public Key
```
[[rules]]
	description = "Public Key"
	regex = '''ssh-rsa'''
	tags = ["keys", "public key"]
```

## Gitlab Key
```
[[rules]]
	description = "Gitlab Key"
	regex = '''privateToken|private-token'''
	tags = ["keys", "Gitlab"]
```

## Generic Credential
```
[[rules]]
	description = "Generic Credential"
	regex = '''(?i)(api_key|apikey|secret)(.{0,20})?['|"][0-9a-zA-Z]{16,45}['|"]'''
	tags = ["key", "API", "generic"]
```

## Google API key
```
[[rules]]
	description = "Google API key"
	regex = '''AIza[0-9A-Za-z\\-_]{35}'''
	tags = ["key", "Google"]
```

## Heroku API key
```
[[rules]]
	description = "Heroku API key"
	regex = '''(?i)heroku(.{0,20})?['"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"]'''
	tags = ["key", "Heroku"]
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

## PayPal Braintree access token
```
[[rules]]
	description = "PayPal Braintree access token"
	regex = '''access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'''
	tags = ["key", "Paypal"]
```

## Picatic API key
```
[[rules]]
	description = "Picatic API key"
	regex = '''sk_live_[0-9a-z]{32}'''
	tags = ["key", "Picatic"]
```

## SendGrid API Key
```
[[rules]]
	description = "SendGrid API Key"
	regex = '''SG\.[\w_]{16,32}\.[\w_]{16,64}'''
	tags = ["key", "SendGrid"]
```

## Stripe API key
```
[[rules]]
	description = "Stripe API key"
	regex = '''(?i)stripe(.{0,20})?['\"][sk|rk]_live_[0-9a-zA-Z]{24}'''
	tags = ["key", "Stripe"]
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


## Twilio API key
```
[[rules]]
	description = "Twilio API key"
	regex = '''(?i)twilio(.{0,20})?['\"][0-9a-f]{32}['\"]'''
	tags = ["key", "twilio"]
```
## system Var

### Env Var
```
[[rules]]
  description = "Env Var"
  regex = '''(?i)(apikey|secret|key|api|password|pass|pw|host)=[0-9a-zA-Z-_.{}]{4,120}'''
```

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

## Port
```
[[rules]]
  description = "Port"
  regex = '''(?i)port(.{0,4})?[0-9]{1,10}'''
  [rules.allowlist]
  	regexes = ['''(?i)port ''']
  	description = "ignore export "
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

## Generic Credential
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

## High Entropy
```
[[rules]]
  description = "WP-Config"
  regex='''define(.{0,20})?(DB_CHARSET|NONCE_SALT|LOGGED_IN_SALT|AUTH_SALT|NONCE_KEY|DB_HOST|DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|DB_NAME|DB_USER)(.{0,20})?['|"].{10,120}['|"]'''
  tags = ["key", "API", "generic"]
```

## High Entropy
```
[[rules]]
	description = "Files with keys and credentials"
    fileNameRegex = '''(?i)(id_rsa|passwd|id_rsa.pub|pgpass|pem|key|shadow)'''
```
