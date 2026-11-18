# Peak level of every audio session (per process) on the default render device, via Windows Core Audio (IAudioMeterInformation).
# Usage: powershell -File audiometer.ps1 -ProcessName gw_demo -Seconds 10 -IntervalMs 100   -> prints max/mean peak (0..1) and the number of samples above 0.001
param([string]$ProcessName = 'gw_demo', [int]$Seconds = 10, [int]$IntervalMs = 100)
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices; using System.Collections.Generic;
public static class Meter {
  [ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")] class MMDeviceEnumeratorCom {}
  [ComImport, Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  interface IMMDeviceEnumerator { int EnumAudioEndpoints(int f, int s, out IntPtr d); int GetDefaultAudioEndpoint(int flow, int role, out IMMDevice dev); }
  [ComImport, Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  interface IMMDevice { int Activate(ref Guid id, int ctx, IntPtr p, [MarshalAs(UnmanagedType.IUnknown)] out object o); }
  [ComImport, Guid("77AA99A0-1BD6-484F-8BC7-2C654C9A9B6F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  interface IAudioSessionManager2 { int a(); int b(); int GetSessionEnumerator(out IAudioSessionEnumerator e); }
  [ComImport, Guid("E2F5BB11-0570-40CA-ACDD-3AA01277DEE8"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  interface IAudioSessionEnumerator { int GetCount(out int n); int GetSession(int i, out IAudioSessionControl s); }
  [ComImport, Guid("F4B1A599-7266-4319-A8CA-E70ACB11E8CD"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  interface IAudioSessionControl { int a(); int b(); int c(); int d(); int e(); int f(); int g(); int h(); int i(); int j(); int k(); }
  [ComImport, Guid("bfb7ff88-7239-4fc9-8fa2-07c950be9c6d"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  interface IAudioSessionControl2 { int a(); int b(); int c(); int d(); int e(); int f(); int g(); int h(); int i();
    int GetSessionIdentifier(out IntPtr s); int GetSessionInstanceIdentifier(out IntPtr s); int GetProcessId(out uint pid); int IsSystemSoundsSession(); int SetDuckingPreference(bool b); }
  [ComImport, Guid("C02216F6-8C67-4B5B-9D00-D008E73E0064"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  interface IAudioMeterInformation { int GetPeakValue(out float p); }
  public static string All() { var sb=new System.Text.StringBuilder();
    var en = (IMMDeviceEnumerator)new MMDeviceEnumeratorCom(); IMMDevice dev; en.GetDefaultAudioEndpoint(0, 1, out dev);
    Guid g = typeof(IAudioSessionManager2).GUID; object o; dev.Activate(ref g, 23, IntPtr.Zero, out o);
    var mgr = (IAudioSessionManager2)o; IAudioSessionEnumerator se; mgr.GetSessionEnumerator(out se); int n; se.GetCount(out n);
    for (int i = 0; i < n; i++) { IAudioSessionControl c; se.GetSession(i, out c); var c2 = (IAudioSessionControl2)c; uint p; c2.GetProcessId(out p); float v; ((IAudioMeterInformation)c).GetPeakValue(out v); sb.Append(p+':'+v.ToString("N4")+' '); }
    return sb.ToString(); }
  public static float Peak(uint pid) {
    var en = (IMMDeviceEnumerator)new MMDeviceEnumeratorCom(); IMMDevice dev; en.GetDefaultAudioEndpoint(0, 1, out dev);
    Guid g = typeof(IAudioSessionManager2).GUID; object o; dev.Activate(ref g, 23, IntPtr.Zero, out o);
    var mgr = (IAudioSessionManager2)o; IAudioSessionEnumerator se; mgr.GetSessionEnumerator(out se); int n; se.GetCount(out n);
    float best = -1;
    for (int i = 0; i < n; i++) { IAudioSessionControl c; se.GetSession(i, out c); var c2 = (IAudioSessionControl2)c; uint p; c2.GetProcessId(out p);
      if (p == pid) { float v; ((IAudioMeterInformation)c).GetPeakValue(out v); if (v > best) best = v; } }
    return best;
  }
}
'@
if ($ProcessName -eq 'LIST') { [Meter]::All(); exit 0 }
$p = Get-Process | Where-Object { $_.ProcessName -like "$ProcessName*" } | Select-Object -First 1
if (-not $p) { 'process not found'; exit 2 }
$vals = New-Object System.Collections.Generic.List[double]
$sw = [Diagnostics.Stopwatch]::StartNew()
while ($sw.Elapsed.TotalSeconds -lt $Seconds) { $v = [Meter]::Peak([uint32]$p.Id); if ($v -ge 0) { $vals.Add($v) }; Start-Sleep -Milliseconds $IntervalMs }
if ($vals.Count -eq 0) { 'no audio session for the process (no audio device opened, or nothing played yet)'; exit 3 }
$m = ($vals | Measure-Object -Maximum -Average)
'samples={0} max={1:N4} mean={2:N4} above0.001={3} above0.01={4}' -f $vals.Count, $m.Maximum, $m.Average, @($vals | Where-Object { $_ -gt 0.001 }).Count, @($vals | Where-Object { $_ -gt 0.01 }).Count
