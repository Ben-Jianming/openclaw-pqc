import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

function assertWindowsPrivateAcl(filePath: string): void {
  // Use SIDs rather than localized account names. A failed inspection is a
  // failed security check, never permission to continue reading the key.
  const pathBase64 = Buffer.from(filePath, "utf8").toString("base64");
  const script = [
    "$ErrorActionPreference = 'Stop'",
    `$keyPath = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${pathBase64}'))`,
    "$acl = [System.IO.File]::GetAccessControl($keyPath)",
    "$me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
    "$owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value",
    "$allowed = @($acl.Access | Where-Object { $_.AccessControlType -eq 'Allow' } | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value })",
    "@{ owner = $owner; user = $me; allowed = $allowed } | ConvertTo-Json -Compress",
  ].join("; ");
  try {
    const command = path.join(
      process.env.SystemRoot ?? "C:\\Windows",
      "System32",
      "WindowsPowerShell",
      "v1.0",
      "powershell.exe",
    );
    const output = execFileSync(command, ["-NoProfile", "-NonInteractive", "-Command", script], {
      encoding: "utf8",
      timeout: 10_000,
      windowsHide: true,
    });
    const acl = JSON.parse(output) as { owner: string; user: string; allowed: string[] };
    if (
      acl.owner !== acl.user ||
      !Array.isArray(acl.allowed) ||
      acl.allowed.some((sid) => sid !== acl.user && sid !== "S-1-5-18")
    ) {
      throw new Error("untrusted owner or access entry");
    }
  } catch {
    throw new Error(
      `Private key file ${filePath} must be owned by the current Windows user and accessible only to that user and SYSTEM; inspect its ACL with icacls.`,
    );
  }
}

export function assertPrivateKeyFile(filePath: string): void {
  const stat = fs.lstatSync(filePath);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`Private key path ${filePath} must be a regular file, not a link`);
  }
  if (process.platform === "win32") {
    assertWindowsPrivateAcl(filePath);
  } else if ((stat.mode & 0o777) !== 0o600) {
    throw new Error(
      `Private key file ${filePath} must be chmod 0600; got 0o${(stat.mode & 0o777).toString(8)}`,
    );
  }
}

function writeWindowsPrivateKeyFile(filePath: string, contents: string): void {
  // The FileStream overload passes this descriptor to CreateFile. The file is
  // never visible with the parent directory's inherited ACL, even briefly.
  const pathBase64 = Buffer.from(filePath, "utf8").toString("base64");
  const script = [
    "$ErrorActionPreference = 'Stop'",
    `$keyPath = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${pathBase64}'))`,
    "$user = [Security.Principal.WindowsIdentity]::GetCurrent().User",
    "$system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')",
    "$security = [Security.AccessControl.FileSecurity]::new()",
    "$security.SetOwner($user)",
    "$security.SetAccessRuleProtection($true, $false)",
    "$allow = [Security.AccessControl.AccessControlType]::Allow",
    "$full = [Security.AccessControl.FileSystemRights]::FullControl",
    "$security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($user, $full, $allow))",
    "$security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($system, $full, $allow))",
    "$stream = $null",
    "try { $stream = [IO.FileStream]::new($keyPath, [IO.FileMode]::CreateNew, [Security.AccessControl.FileSystemRights]::Write, [IO.FileShare]::None, 4096, [IO.FileOptions]::None, $security); try { [Console]::OpenStandardInput().CopyTo($stream); $stream.Flush($true) } finally { $stream.Dispose() } } catch { if ($null -ne $stream) { try { [IO.File]::Delete($keyPath) } catch {} }; throw }",
  ].join("; ");
  const command = path.join(
    process.env.SystemRoot ?? "C:\\Windows",
    "System32",
    "WindowsPowerShell",
    "v1.0",
    "powershell.exe",
  );
  execFileSync(
    command,
    [
      "-NoProfile",
      "-NonInteractive",
      "-EncodedCommand",
      Buffer.from(script, "utf16le").toString("base64"),
    ],
    {
      input: Buffer.from(contents, "utf8"),
      encoding: "utf8",
      timeout: 10_000,
      windowsHide: true,
    },
  );
}

function syncDirectory(directoryPath: string): void {
  const fd = fs.openSync(directoryPath, "r");
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

export function writePrivateKeyFile(filePath: string, contents: string): string {
  const absolute = path.resolve(filePath);
  const parent = path.dirname(absolute);
  const firstCreatedDirectory = fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  if (process.platform === "win32" && fs.existsSync(absolute)) {
    throw new Error(`Private key file ${absolute} already exists`);
  }
  let created = false;
  let completed = false;
  try {
    if (process.platform === "win32") {
      writeWindowsPrivateKeyFile(absolute, contents);
      created = true;
    } else {
      const fd = fs.openSync(absolute, "wx", 0o600);
      created = true;
      try {
        fs.chmodSync(absolute, 0o600);
        fs.writeFileSync(fd, contents, { encoding: "utf8" });
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
    }
    assertPrivateKeyFile(absolute);
    if (process.platform !== "win32") {
      // Persist the file's directory entry and every directory created above
      // it before a caller may commit an identity encrypted under this key.
      const stop = firstCreatedDirectory ? path.dirname(firstCreatedDirectory) : parent;
      for (let current = parent; ; current = path.dirname(current)) {
        syncDirectory(current);
        if (current === stop) {
          break;
        }
      }
    }
    completed = true;
  } finally {
    if (created && !completed) {
      try {
        fs.rmSync(absolute, { force: true });
      } catch {
        // Preserve the actual ACL/write failure for the caller.
      }
    }
  }
  return absolute;
}
