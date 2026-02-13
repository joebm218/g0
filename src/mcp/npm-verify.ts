export interface MCPVerifyResult {
  package: string;
  version: string;
  found: boolean;
  publisher?: string;
  maintainers: string[];
  publishedAt?: string;
  packageAge?: number; // days since first published
  weeklyDownloads?: number;
  dependencies: string[];
  hasInstallScripts: boolean;
  installScripts: string[];
  license?: string;
  repository?: string;
  risks: MCPVerifyRisk[];
  overallRisk: 'low' | 'medium' | 'high' | 'critical';
}

export interface MCPVerifyRisk {
  severity: 'critical' | 'high' | 'medium' | 'low';
  type: string;
  description: string;
}

interface NpmPackageData {
  name: string;
  version: string;
  description?: string;
  license?: string;
  repository?: { url?: string };
  maintainers?: { name: string; email?: string }[];
  time?: Record<string, string>;
  'dist-tags'?: Record<string, string>;
  versions?: Record<string, {
    scripts?: Record<string, string>;
    dependencies?: Record<string, string>;
    _npmUser?: { name: string };
  }>;
}

interface NpmDownloadsData {
  downloads?: number;
}

/**
 * Verify an MCP server npm package for security signals.
 */
export async function verifyNpmPackage(packageName: string): Promise<MCPVerifyResult> {
  const result: MCPVerifyResult = {
    package: packageName,
    version: 'unknown',
    found: false,
    maintainers: [],
    dependencies: [],
    hasInstallScripts: false,
    installScripts: [],
    risks: [],
    overallRisk: 'low',
  };

  // Fetch package metadata from npm registry
  let data: NpmPackageData;
  try {
    const response = await fetch(`https://registry.npmjs.org/${encodeURIComponent(packageName)}`);
    if (response.status === 404) {
      result.risks.push({
        severity: 'critical',
        type: 'not-found',
        description: `Package "${packageName}" not found on npm registry`,
      });
      result.overallRisk = 'critical';
      return result;
    }
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    data = await response.json() as NpmPackageData;
  } catch (err) {
    result.risks.push({
      severity: 'high',
      type: 'fetch-error',
      description: `Failed to fetch package data: ${err instanceof Error ? err.message : String(err)}`,
    });
    result.overallRisk = 'high';
    return result;
  }

  result.found = true;
  const latestVersion = data['dist-tags']?.latest ?? Object.keys(data.versions ?? {}).pop() ?? 'unknown';
  result.version = latestVersion;

  // Maintainers
  if (data.maintainers) {
    result.maintainers = data.maintainers.map(m => m.name);
  }

  // Publisher
  const latestMeta = data.versions?.[latestVersion];
  if (latestMeta?._npmUser) {
    result.publisher = latestMeta._npmUser.name;
  }

  // License
  result.license = data.license;

  // Repository
  if (data.repository?.url) {
    result.repository = data.repository.url.replace(/^git\+/, '').replace(/\.git$/, '');
  }

  // Published time & package age
  if (data.time) {
    const createdTime = data.time.created;
    const latestTime = data.time[latestVersion];
    if (createdTime) {
      const ageMs = Date.now() - new Date(createdTime).getTime();
      result.packageAge = Math.floor(ageMs / (1000 * 60 * 60 * 24));
    }
    if (latestTime) {
      result.publishedAt = latestTime;
    }
  }

  // Dependencies
  if (latestMeta?.dependencies) {
    result.dependencies = Object.keys(latestMeta.dependencies);
  }

  // Install scripts
  if (latestMeta?.scripts) {
    const dangerousScripts = ['preinstall', 'install', 'postinstall', 'preuninstall', 'postuninstall'];
    for (const scriptName of dangerousScripts) {
      if (latestMeta.scripts[scriptName]) {
        result.hasInstallScripts = true;
        result.installScripts.push(`${scriptName}: ${latestMeta.scripts[scriptName]}`);
      }
    }
  }

  // Fetch weekly downloads
  try {
    const dlResp = await fetch(`https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(packageName)}`);
    if (dlResp.ok) {
      const dlData = await dlResp.json() as NpmDownloadsData;
      result.weeklyDownloads = dlData.downloads;
    }
  } catch {
    // Non-critical, skip
  }

  // Risk analysis
  analyzeRisks(result);

  return result;
}

function analyzeRisks(result: MCPVerifyResult): void {
  // Install scripts
  if (result.hasInstallScripts) {
    result.risks.push({
      severity: 'high',
      type: 'install-scripts',
      description: `Package has install scripts that execute during npm install: ${result.installScripts.join('; ')}`,
    });
  }

  // Package age
  if (result.packageAge !== undefined && result.packageAge < 30) {
    result.risks.push({
      severity: 'medium',
      type: 'new-package',
      description: `Package is only ${result.packageAge} days old — higher risk of being malicious or unmaintained`,
    });
  }

  // Low downloads
  if (result.weeklyDownloads !== undefined && result.weeklyDownloads < 100) {
    result.risks.push({
      severity: 'medium',
      type: 'low-downloads',
      description: `Package has only ${result.weeklyDownloads} weekly downloads — limited community vetting`,
    });
  }

  // Single maintainer
  if (result.maintainers.length === 1) {
    result.risks.push({
      severity: 'low',
      type: 'single-maintainer',
      description: 'Package has only one maintainer — higher bus factor risk',
    });
  }

  // No repository
  if (!result.repository) {
    result.risks.push({
      severity: 'medium',
      type: 'no-repository',
      description: 'Package has no linked source repository — cannot verify source code',
    });
  }

  // No license
  if (!result.license) {
    result.risks.push({
      severity: 'low',
      type: 'no-license',
      description: 'Package has no declared license',
    });
  }

  // Many dependencies
  if (result.dependencies.length > 20) {
    result.risks.push({
      severity: 'medium',
      type: 'many-dependencies',
      description: `Package has ${result.dependencies.length} dependencies — large attack surface`,
    });
  }

  // Calculate overall risk
  const severityOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
  let maxRisk = 0;
  for (const risk of result.risks) {
    maxRisk = Math.max(maxRisk, severityOrder[risk.severity] ?? 0);
  }
  if (maxRisk >= 4) result.overallRisk = 'critical';
  else if (maxRisk >= 3) result.overallRisk = 'high';
  else if (maxRisk >= 2) result.overallRisk = 'medium';
  else result.overallRisk = 'low';
}
