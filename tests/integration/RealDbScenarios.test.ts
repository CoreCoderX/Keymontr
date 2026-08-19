import * as path from "path";
import { Pipeline } from "../../src/core/pipeline/Pipeline";
import { DatabaseManager } from "../../src/database/DatabaseManager";
import { ConfigurationManager } from "../../src/config/ConfigurationManager";
import { Gate8_DeveloperMemory } from "../../src/core/pipeline/Gate8_DeveloperMemory";

const REPO_ROOT = path.resolve(__dirname, "..", "..");

interface FindingLike {
  candidate: { lineNumber: number; value: string };
  confidence: { finalScore: number };
  severity: string;
  detection: {
    matchedRuleId?: string;
    matchedGroup?: string;
    isKnownProvider?: boolean;
  };
  remediation: { suggestedEnvKey: string };
}

describe("Real DB Scenarios (user acceptance)", () => {
  let pipeline: Pipeline;

  beforeAll(async () => {
    DatabaseManager.reset();
    const dbManager = DatabaseManager.getInstance();
    await dbManager.initialize(REPO_ROOT);
    const config = new ConfigurationManager();
    config.load(REPO_ROOT);
    pipeline = new Pipeline(dbManager, config, new Gate8_DeveloperMemory());
  });

  afterAll(() => {
    DatabaseManager.reset();
  });

  function run(content: string, fileUri: string, languageId: string) {
    return pipeline.run({
      fileUri,
      fileContent: content,
      languageId,
      triggerType: "save",
    });
  }

  function byLine(
    findings: FindingLike[],
    lineNumber1Based: number,
  ): FindingLike | undefined {
    return findings.find(
      (f) => f.candidate.lineNumber + 1 === lineNumber1Based,
    );
  }

  it("config.ts: AWS keys, GitHub PAT, payment key, JWT — accurate rules & severities", async () => {
    const content = `
import axios from "axios";

export const AppConfig = {
  awsAccessKeyId: "AKIA9876543210ZYXWVU",
  awsSecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCY123456789",

  githubToken: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",

  paymentApiKey: "xK9mP2qR5vN8wL1jB4hT7yZ0cA3eFgDi6uS9bE",

  testToken: "sk-1234567890abcdefghijT3BlbkFJ1234567890abcdefghij", // keymontr-ignore
};

export async function fetchData() {
  const secret =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
  return axios.get("https://api.example.com/data", {
    headers: {
      Authorization: \`Bearer \${secret}\`,
      "Content-Type": "application/json",
    },
  });
}
    `.trim();

    const result = await run(
      content,
      path.join(REPO_ROOT, "acceptance", "config.ts"),
      "typescript",
    );

    // 1. AWS Access Key ID → specific aws-access-token rule, CRITICAL
    const awsKey = byLine(result.findings as unknown as FindingLike[], 4);
    expect(awsKey?.detection.matchedRuleId).toBe("aws-access-token");
    expect(awsKey?.severity).toBe("critical");
    expect(awsKey?.remediation.suggestedEnvKey).toBe("AWS_ACCESS_TOKEN");

    // 2. AWS Secret Access Key → CRITICAL (provider-context floor), env from identifier
    const awsSecret = byLine(result.findings as unknown as FindingLike[], 5);
    expect(awsSecret?.severity).toBe("critical");
    expect(awsSecret?.remediation.suggestedEnvKey).toBe(
      "AWS_SECRET_ACCESS_KEY",
    );

    // 3. GitHub PAT → github-pat rule, CRITICAL
    const gh = byLine(result.findings as unknown as FindingLike[], 7);
    expect(gh?.detection.matchedRuleId).toBe("github-pat");
    expect(gh?.severity).toBe("critical");
    expect(gh?.remediation.suggestedEnvKey).toBe("GITHUB_PAT");

    // 4. paymentApiKey → HIGH (not CRITICAL), env from assignment identifier
    const payment = byLine(result.findings as unknown as FindingLike[], 9);
    expect(payment?.severity).toBe("high");
    expect(payment?.remediation.suggestedEnvKey).toBe("PAYMENT_API_KEY");
    expect(payment?.confidence.finalScore).toBeLessThan(0.88);

    // 5. keymontr-ignore line → suppressed entirely
    expect(byLine(result.findings as unknown as FindingLike[], 13)).toBeUndefined();

    // 6. JWT → jwt rule, CRITICAL
    const jwt = byLine(result.findings as unknown as FindingLike[], 16);
    expect(jwt?.detection.matchedRuleId).toBe("jwt");
    expect(jwt?.severity).toBe("critical");
    expect(jwt?.remediation.suggestedEnvKey).toBe("JWT");
  });

  it("DatabaseConfig.java: Azure key, hardcoded password, RSA private key", async () => {
    const content = `
public class DatabaseConfig {
    
    private static final String AZURE_STORAGE_KEY = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";

    public String getDbPassword() {
        return "Pr0duction_DB_P@ssw0rd!2024";
    }

    public static final String PRIVATE_KEY = 
        "-----BEGIN RSA PRIVATE KEY-----\\n" +
        "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB\\n" +
        "-----END RSA PRIVATE KEY-----";
}
    `.trim();

    const result = await run(
      content,
      path.join(REPO_ROOT, "acceptance", "DatabaseConfig.java"),
      "java",
    );

    // 1. Azure storage key → CRITICAL (provider-context floor), env from identifier
    const azure = byLine(result.findings as unknown as FindingLike[], 3);
    expect(azure?.severity).toBe("critical");
    expect(azure?.remediation.suggestedEnvKey).toBe("AZURE_STORAGE_KEY");

    // 2. Hardcoded password (isolated on its own line) → MEDIUM or HIGH
    const password = byLine(result.findings as unknown as FindingLike[], 6);
    expect(["medium", "high"]).toContain(password?.severity);

    // 3. RSA PRIVATE KEY header fragment → CRITICAL (PEM floor)
    const pem = byLine(result.findings as unknown as FindingLike[], 10);
    expect(pem?.severity).toBe("critical");
  });
});