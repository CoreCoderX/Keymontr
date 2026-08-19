import { CollisionResolver } from "../../../src/database/CollisionResolver";
import { CompiledRule } from "../../../src/core/types/RuleDefinition";

describe("CollisionResolver", () => {
  let resolver: CollisionResolver;

  beforeEach(() => {
    resolver = new CollisionResolver();
  });

  const openaiRule: CompiledRule = {
    id: "openai-api-key",
    description: "OpenAI API Key",
    regex: /sk-proj-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/,
    rawRegex: "sk-proj-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}",
    entropy: 3.0,
    keywords: ["sk-"],
    secretGroup: 1,
    allowlists: [],
  };

  const genericRule: CompiledRule = {
    id: "generic-api-key",
    description: "Generic API Key",
    regex: /(?:api[\s_-]?key|apikey|key)[^0-9a-zA-Z\n]{0,10}([a-zA-Z0-9_-]{20,64})/i,
    rawRegex:
      "(?:api[\\s_-]?key|apikey|key)[^0-9a-zA-Z\\n]{0,10}([a-zA-Z0-9_-]{20,64})",
    entropy: 3.5,
    keywords: ["api_key", "apikey", "api-key", "key"],
    secretGroup: 1,
    allowlists: [],
  };

  const sendgridRule: CompiledRule = {
    id: "sendgrid-api-token",
    description: "SendGrid API Token",
    regex: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/,
    rawRegex: "SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}",
    entropy: 3.0,
    keywords: ["sg."],
    secretGroup: 0,
    allowlists: [],
  };

  const openaiLine =
    'const OPENAI_API_KEY = "sk-proj-AAAAAAAAAAAAAAAAAAAAT3BlbkFJBBBBBBBBBBBBBBBBBBBB";';

  it("prefers the specific provider rule over generic-api-key on a score tie", () => {
    // Generic rule listed FIRST to prove insertion order no longer decides the tie.
    const resolutions = resolver.resolveCollisions(
      "sk-proj-AAAAAAAAAAAAAAAAAAAAT3BlbkFJBBBBBBBBBBBBBBBBBBBB",
      openaiLine,
      [genericRule, openaiRule],
    );

    const best = resolver.getBestResolution(resolutions);
    expect(best?.ruleId).toBe("openai-api-key");
    // Generic rules score lower (0.8) than specific provider rules (0.92),
    // so the specific rule wins on score — not just on the tie-break.
    expect(resolutions[0]?.ruleId).toBe("openai-api-key");
    expect(resolutions[0]?.score).toBeGreaterThan(resolutions[1]?.score ?? 0);
    expect(resolutions[1]?.ruleId).toBe("generic-api-key");
  });

  it("keeps generic-api-key when it is the only rule that matches", () => {
    const resolutions = resolver.resolveCollisions(
      "xK9mP2qR5vN8wL1jB4hT7yZ0cA3eFgDi6uS",
      'const API_KEY = "xK9mP2qR5vN8wL1jB4hT7yZ0cA3eFgDi6uS";',
      [openaiRule, genericRule],
    );

    const best = resolver.getBestResolution(resolutions);
    expect(best?.ruleId).toBe("generic-api-key");
  });

  it("prefers specific rules even when the generic rule is inserted first", () => {
    const line =
      'const SENDGRID_API_KEY = "SG.abcdefghijklmnopqrstuv.1234567890123456789012345678901234567890123";';

    const resolutions = resolver.resolveCollisions(
      "SG.abcdefghijklmnopqrstuv.1234567890123456789012345678901234567890123",
      line,
      [genericRule, sendgridRule],
    );

    const best = resolver.getBestResolution(resolutions);
    expect(best?.ruleId).toBe("sendgrid-api-token");
  });

  it("breaks ties deterministically between two specific rules", () => {
    const line =
      'const SENDGRID_API_KEY = "SG.abcdefghijklmnopqrstuv.1234567890123456789012345678901234567890123";';

    const resolutions = resolver.resolveCollisions(
      "SG.abcdefghijklmnopqrstuv.1234567890123456789012345678901234567890123",
      line,
      [sendgridRule, sendgridRule],
    );

    const best = resolver.getBestResolution(resolutions);
    expect(best?.ruleId).toBe("sendgrid-api-token");
  });
});