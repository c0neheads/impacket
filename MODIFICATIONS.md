# Impacket IOC Modifications

Documentation of hardcoded Indicator of Compromise (IOC) changes made for authorized adversary emulation engagements. Changes are intended to replace well-known, signature-detected default strings with operator-controlled values to enable realistic threat emulation.

---

## psexec.py + remcomsvc.py + serviceinstall.py

### Background

`psexec.py` executes commands on remote systems by installing a service that runs a bundled binary (`RemComSvc`). The binary communicates back to the operator via named pipes over SMB. All pipe names, the service name, and the dropped binary name are well-known IOCs detected by endpoint and network security products.

The changes below span three files because the pipe names exist in two places that must stay in sync:
- The compiled binary blob embedded in `remcomsvc.py` (creates the pipes on the target)
- The Python constants in `psexec.py` (connects to those pipes)

### Changes

#### `impacket/examples/remcomsvc.py` — Binary patch

The `REMCOMSVC` variable is a hexlified PE binary. Four pipe name strings were patched directly in the binary at their respective offsets. Replacement strings are the same byte length as the originals (padded with null bytes) to preserve binary structure.

| Offset | Original string | Replacement |
|--------|----------------|-------------|
| 39428 | `RemCom_stderr` (13 bytes) | `cone_stderr\x00\x00` |
| 39444 | `RemCom_stdin` (12 bytes) | `cone_stdin\x00\x00` |
| 39476 | `RemCom_stdout` (13 bytes) | `cone_stdout\x00\x00` |
| 39505 | `RemCom_communicaton` (19 bytes) | `cone_communicaton\x00\x00` |

#### `examples/psexec.py` — Python pipe name constants

```python
# Before
RemComSTDOUT = "RemCom_stdout"
RemComSTDIN  = "RemCom_stdin"
RemComSTDERR = "RemCom_stderr"

# After
RemComSTDOUT = "cone_stdout"
RemComSTDIN  = "cone_stdin"
RemComSTDERR = "cone_stderr"
```

Main communication pipe opened in `doStuff()`:

```python
# Before
fid_main = self.openPipe(s, tid, r'\RemCom_communicaton', 0x12019f)

# After
fid_main = self.openPipe(s, tid, r'\cone_communicaton', 0x12019f)
```

#### `impacket/examples/serviceinstall.py` — Service and binary names

```python
# Before — randomized per run
self.__service_name      = ''.join([random.choice(string.ascii_letters) for i in range(4)])
self.__binary_service_name = ''.join([random.choice(string.ascii_letters) for i in range(8)]) + '.exe'

# After — static
self.__service_name        = 'cone'
self.__binary_service_name = 'conesvc.exe'
```

Removed now-unused `import random` and `import string`.

> **Note:** The `-service-name` and `-remote-binary-name` CLI flags on `psexec.py` still function and will override these defaults at runtime if further customization is needed per engagement.

### IOC Comparison

| IOC Type | Original (detected) | Modified |
|----------|-------------------|----------|
| Main named pipe | `\RemCom_communicaton` | `\cone_communicaton` |
| stdout pipe | `RemCom_stdout[MACHINE][PID]` | `cone_stdout[MACHINE][PID]` |
| stdin pipe | `RemCom_stdin[MACHINE][PID]` | `cone_stdin[MACHINE][PID]` |
| stderr pipe | `RemCom_stderr[MACHINE][PID]` | `cone_stderr[MACHINE][PID]` |
| Service name | random 4-char alpha | `cone` |
| Dropped binary | random 8-char alpha`.exe` | `conesvc.exe` |

---

---

## smbexec.py

### Background

`smbexec.py` executes commands by creating a short-lived service per command. The service runs a batch file that redirects output to a file on a writable share, which is then read back and deleted. In `SERVER` mode, a local SMB server is stood up to receive output when no writable share is available on the target.

### Changes

#### `examples/smbexec.py` — Output file, local server artifacts, service name, batch file

```python
# Before
OUTPUT_FILENAME = '__output_' + ''.join([random.choice(string.ascii_letters) for i in range(8)])
SMBSERVER_DIR   = '__tmp'
DUMMY_SHARE     = 'TMP'

# After
OUTPUT_FILENAME = 'cone_output'
SMBSERVER_DIR   = 'cone_tmp'
DUMMY_SHARE     = 'CONE'
```

```python
# Before — service name randomized per session
self.__serviceName = ''.join([random.choice(string.ascii_letters) for i in range(8)])

# After
self.__serviceName = 'cone'
```

```python
# Before — batch file randomized per command
batchFile = '%SYSTEMROOT%\\' + ''.join([random.choice(string.ascii_letters) for _ in range(8)]) + '.bat'

# After
batchFile = '%SYSTEMROOT%\\conesvc.bat'
```

Removed now-unused `import random` and `import string`.

### IOC Comparison

| IOC Type | Original (detected) | Modified |
|----------|-------------------|----------|
| Output file on share | `__output_[A-Za-z]{8}` | `cone_output` |
| Batch file on target | `%SYSTEMROOT%\[A-Za-z]{8}.bat` | `%SYSTEMROOT%\conesvc.bat` |
| Service name | random 8-char alpha | `cone` |
| Local temp dir (SERVER mode) | `__tmp` | `cone_tmp` |
| Local share name (SERVER mode) | `TMP` | `CONE` |

---

---

## wmiexec.py

### Background

`wmiexec.py` executes commands via WMI `Win32_Process.Create()`. Output is redirected to a file on a share (default `ADMIN$`), read back, and deleted. No service is created — execution runs under the authenticated user context rather than SYSTEM.

### Changes

#### `examples/wmiexec.py` — Output filename

```python
# Before — timestamp changes each run but pattern is always __[float]
OUTPUT_FILENAME = '__' + str(time.time())

# After
OUTPUT_FILENAME = 'cone_output'
```

### IOC Comparison

| IOC Type | Original (detected) | Modified |
|----------|-------------------|----------|
| Output file on share | `__[unix_timestamp]` (e.g. `__1708123456.789`) | `cone_output` |

---

---

## atexec.py

### Background

`atexec.py` executes commands by registering a one-shot scheduled task via the Task Scheduler RPC interface (`\pipe\atsvc`). Output is redirected to a `.tmp` file in `%windir%\Temp`, retrieved over SMB, then deleted. The task is deleted immediately after running. The hardcoded `StartBoundary` date has been a reliable, stable IOC since the tool was written and appears verbatim in numerous detection signatures.

### Changes

#### `examples/atexec.py` — Task name and output filename

```python
# Before — randomized per run
tmpName = ''.join([random.choice(string.ascii_letters) for _ in range(8)])

# After
tmpName = 'cone'
```

`tmpFileName` is derived from `tmpName` (`tmpName + '.tmp'`), so the output file becomes `cone.tmp` automatically.

#### `examples/atexec.py` — Scheduled task start boundary

```xml
<!-- Before -->
<StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>

<!-- After -->
<StartBoundary>2023-10-12T14:48:22.3865091</StartBoundary>
```

Removed now-unused `import string` and `import random`.

### IOC Comparison

| IOC Type | Original (detected) | Modified |
|----------|-------------------|----------|
| Scheduled task name | `\[A-Za-z]{8}` | `\cone` |
| Output file | `%windir%\Temp\[A-Za-z]{8}.tmp` | `%windir%\Temp\cone.tmp` |
| Task XML StartBoundary | `2015-07-15T20:35:13.2757294` | `2023-10-12T14:48:22.3865091` |

---

---

## dcomexec.py

### Background

`dcomexec.py` executes commands via DCOM using one of three COM objects (`MMC20.Application`, `ShellWindows`, `ShellBrowserWindow`). Like `wmiexec.py`, output is redirected to a file on a share, read back, and deleted. No service is created.

### Changes

#### `examples/dcomexec.py` — Output filename

```python
# Before — first 5 digits of unix timestamp, e.g. __17081
OUTPUT_FILENAME = '__' + str(time.time())[:5]

# After
OUTPUT_FILENAME = 'cone_output'
```

### IOC Comparison

| IOC Type | Original (detected) | Modified |
|----------|-------------------|----------|
| Output file on share | `__[0-9]{5}` (e.g. `__17081`) | `cone_output` |

---

---

## wmipersist.py

### Background

`wmipersist.py` installs WMI event subscriptions for persistence using `ActiveScriptEventConsumer`. Three WMI objects are created in the `root\subscription` namespace: an event consumer, an event filter (or timer), and a binding between them. The `EF_` and `TI_` prefixes on object names and the hardcoded `CreatorSID` value are all consistent fingerprints across every deployment.

### Changes

#### `examples/wmipersist.py` — EventFilter prefix (8 occurrences)

```python
# Before
eventFilter.Name = 'EF_%s' % self.__options.name

# After
eventFilter.Name = 'CF_%s' % self.__options.name
```

#### `examples/wmipersist.py` — TimerInstruction prefix (4 occurrences)

```python
# Before
wmiTimer.TimerId = 'TI_%s' % self.__options.name

# After
wmiTimer.TimerId = 'CT_%s' % self.__options.name
```

#### `examples/wmipersist.py` — CreatorSID (4 occurrences)

```python
# Before — S-1-5-32-544 (Administrators group), hardcoded on all WMI objects
CreatorSID = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]

# After — S-1-5-32-545 (Users group)
CreatorSID = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 33, 2, 0, 0]
```

The original `S-1-5-32-544` (Administrators) SID appears identically on every impacket WMI subscription and is a stable byte-level detection. The replacement `S-1-5-32-545` (Users) is structurally valid and the same length.

### IOC Comparison

| IOC Type | Original (detected) | Modified |
|----------|-------------------|----------|
| EventFilter name prefix | `EF_[name]` | `CF_[name]` |
| TimerInstruction ID prefix | `TI_[name]` | `CT_[name]` |
| FilterToConsumerBinding filter ref | `EF_[name]` | `CF_[name]` |
| CreatorSID on all 3 WMI objects | `S-1-5-32-544` (Admins) | `S-1-5-32-545` (Users) |

---

---

## secretsdump.py

### Background

`secretsdump.py` extracts credentials remotely via registry hive saves (SAM, SECURITY, SYSTEM), VSS shadow copy (NTDS.dit), or DRSUAPI (DCSync). Remote execution methods (`smbexec`, `wmiexec`, `mmcexec`) are used to run vssadmin commands and copy files. Each method leaves artifacts on the target — output files, batch files, and temp service names — all previously randomised but pattern-detectable.

### Changes

#### `impacket/examples/secretsdump.py` — Batch and output file names (lines 454, 456)

```python
# Before
self.__batchFile = '%TEMP%\\execute.bat'
self.__output    = '%SYSTEMROOT%\\Temp\\__output'

# After
self.__batchFile = '%TEMP%\\cone.bat'
self.__output    = '%SYSTEMROOT%\\Temp\\cone_out'
```

#### `impacket/examples/secretsdump.py` — Hardcoded output file references (lines 1177, 1211, 1273, 1283)

These four lines bypass `self.__output` and reference the path directly. All updated to match:

```python
# Before
'Temp\\__output'

# After
'Temp\\cone_out'
```

#### `impacket/examples/secretsdump.py` — Registry hive temp filenames (line 971)

`__retrieveHive()` is called once each for SAM, SECURITY, and SYSTEM. Static names must be unique per call to avoid collisions. The hive name is used as a differentiator:

```python
# Before — random per call
tmpFileName = ''.join([random.choice(string.ascii_letters) for _ in range(8)]) + '.tmp'

# After — unique per hive, predictable
tmpFileName = hiveName.lower() + '_cone.tmp'
# Results in: sam_cone.tmp, security_cone.tmp, system_cone.tmp
```

#### `impacket/examples/secretsdump.py` — Temp service name (line 1148)

```python
# Before — random per remote exec call
self.__tmpServiceName = ''.join([random.choice(string.ascii_letters) for _ in range(8)])

# After
self.__tmpServiceName = 'cone'
```

#### `impacket/examples/secretsdump.py` — NTDS copy temp filename (line 1261)

```python
# Before
tmpFileName = ''.join([random.choice(string.ascii_letters) for _ in range(8)]) + '.tmp'

# After
tmpFileName = 'cone_ntds.tmp'
```

#### `impacket/examples/secretsdump.py` — Session resume filename (line 2416)

Local file on the operator machine, still an identifiable pattern:

```python
# Before
self.__resumeFileName = 'sessionresume_%s' % ''.join(random.choice(string.ascii_letters) for _ in range(8))

# After
self.__resumeFileName = 'sessionresume_cone'
```

Note: `import random` and `import string` are retained — they are still required for cryptographic key generation elsewhere in the file.

### IOC Comparison

| IOC Type | Original (detected) | Modified |
|----------|-------------------|----------|
| Remote batch file | `%TEMP%\execute.bat` | `%TEMP%\cone.bat` |
| Remote output file | `%SYSTEMROOT%\Temp\__output` | `%SYSTEMROOT%\Temp\cone_out` |
| Registry hive temp files | `[A-Za-z]{8}.tmp` | `sam_cone.tmp`, `security_cone.tmp`, `system_cone.tmp` |
| NTDS copy temp file | `[A-Za-z]{8}.tmp` | `cone_ntds.tmp` |
| Temp service name | random 8-char alpha | `cone` |
| Session resume file (local) | `sessionresume_[A-Za-z]{8}` | `sessionresume_cone` |
