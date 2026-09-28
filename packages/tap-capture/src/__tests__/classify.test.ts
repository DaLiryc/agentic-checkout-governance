import { describe, it, expect } from 'vitest'
import { classifyAgentUA } from '../classify'

describe('classifyAgentUA', () => {
  it('classifies OpenAI Operator', () => {
    expect(classifyAgentUA('OpenAI Operator/1.0 (+https://operator.openai.com)')).toBe(
      'openai-operator',
    )
  })

  it('classifies ChatGPT bots', () => {
    expect(classifyAgentUA('ChatGPT-UserAgent/1.0')).toBe('chatgpt')
  })

  it('classifies Claude bots (not as generic bot)', () => {
    expect(classifyAgentUA('Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claude-bot@anthropic.com)')).toBe(
      'claude',
    )
  })

  it('classifies Perplexity bots', () => {
    expect(classifyAgentUA('Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)')).toBe(
      'perplexity',
    )
  })

  it('classifies Amazon Nova act', () => {
    expect(classifyAgentUA('Amazon-Nova-Act/1.0')).toBe('amazon-nova')
    expect(classifyAgentUA('AmazonNovaAct/0.9')).toBe('amazon-nova')
  })

  it('classifies generic bots, spiders, and headless browsers as unknown-bot', () => {
    expect(classifyAgentUA('Mozilla/5.0 (compatible; AcmeBot/1.0)')).toBe('unknown-bot')
    expect(classifyAgentUA('SomeSpider/2.1 (+http://example.com)')).toBe('unknown-bot')
    expect(classifyAgentUA('Mozilla/5.0 HeadlessChrome/120.0.0.0')).toBe('unknown-bot')
  })

  it('classifies human browsers as human', () => {
    expect(
      classifyAgentUA(
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36',
      ),
    ).toBe('human')
  })

  it('classifies empty, null, and undefined as human', () => {
    expect(classifyAgentUA('')).toBe('human')
    expect(classifyAgentUA(null)).toBe('human')
    expect(classifyAgentUA(undefined)).toBe('human')
  })
})
