# FakeNet-NG Setup

Loonaro uses [Mandiant's FakeNet-NG](https://github.com/mandiant/flare-fakenet-ng) for network simulation and PCAP capture. This might get detected as a false positive by some antivirus software and is thus not included directly in the repository.

## Download

1. Go to [FakeNet-NG Releases](https://github.com/mandiant/flare-fakenet-ng/releases)
2. Download the latest Windows release (e.g., `fakenet1.4.11.zip`)
3. Extract to `tools/fakenet-ng/`

```
tools/
└── fakenet-ng/
    ├── fakenet.exe
    ├── configs/
    │   └── default.ini
    └── listeners/
```

## Configuration

The Monitor auto-generates `fakenet.ini` per session with:
- PCAP output: `{session_id}.pcap`
- DNS responses: `192.0.2.1`
- HTTP/HTTPS listeners

## Environment Variable

Override FakeNet-NG path:
```
$env:FAKENET_PATH = "C:\path\to\fakenet.exe"
```

## Verify

FakeNet-NG requires admin privileges. Test:
```powershell
cd tools\fakenet-ng
.\fakenet.exe -h
```

## Output

Each analysis session produces:
- `{session_id}.pcap` - Full packet capture
- `fakenet.ini` - Generated config
