# Registry Interop Tests

1. Put [registry_interop_test_rules.json](/D:/Code/driver/HostGuard/registry_interop_test_rules.json) next to `HostGuard.exe` and rename it to `rules.json`.
2. Start `HostGuard.exe` as administrator and confirm it logs that registry rules were loaded.
3. Run `powershell -ExecutionPolicy Bypass -File .\RegistryInteropTests.ps1` in the same directory.

Covered operations:

- `create_key`
- `set_value`
- `delete_value`
- `delete_key`
- `rename_key`
- `set_information_key` using `NtSetInformationKey(..., KeyWriteTimeInformation, ...)`

Expected result:

- Each step should report `blocked or failed`.
- `HostGuard.exe` should print a registry block event with `操作类型`, `规则 ID`, `注册表路径`, and when applicable `InfoClass` / `值名称` / `新名称` / `值数据`.

Notes:

- The rules intentionally match `powershell.exe`, so run the script from PowerShell.
- The test key root is `HKCU:\Software\HostGuardInterop`.
- Driver-side matching uses the kernel registry path, so the sample rules match on `\\software\\hostguardinterop\\...` instead of hardcoding the current user SID.
