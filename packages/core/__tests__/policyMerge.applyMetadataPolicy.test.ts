import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { combineMetadataPolicies } from '../src/resolveTrustChains/policies/combineMetadataPolicies'
import type { SignCallback, VerifyCallback } from '../src/utils'
import { setupConfigurationChain, subordinateStatements } from './utils/setupConfigurationChain'

describe('policy merge', () => {
  const signJwtCallback: SignCallback = () => Promise.resolve(new Uint8Array(10).fill(42))
  const _verifyJwtCallback: VerifyCallback = () => Promise.resolve(true)

  // add

  it('should combine add metadata policies', async () => {
    const leafEntityId = 'https://leaf.example.org'
    const intermediateEntityId = 'https://intermediate.example.org'
    const trustAnchorEntityId = 'https://trust.example.org'

    const { chainData: configurations } = await setupConfigurationChain(
      [
        { entityId: leafEntityId, authorityHints: [intermediateEntityId] },
        {
          entityId: intermediateEntityId,
          authorityHints: [trustAnchorEntityId],
          subordinates: [
            {
              entityId: leafEntityId,
              claims: {
                metadata_policy: {
                  openid_relying_party: {
                    contacts: {
                      add: ['ops@intermediate.example.org'],
                    },
                  },
                },
              },
            },
          ],
        },
        {
          entityId: trustAnchorEntityId,
          subordinates: [
            {
              entityId: intermediateEntityId,
              claims: {
                metadata_policy: {
                  openid_relying_party: {
                    contacts: {
                      add: ['ops@ta.example.org'],
                    },
                  },
                },
              },
            },
          ],
        },
      ],
      { signJwtCallback, mockEndpoints: true }
    )

    const statements = subordinateStatements(configurations)

    const { mergedPolicy } = await combineMetadataPolicies({ statements })

    assert.deepStrictEqual(mergedPolicy, {
      openid_relying_party: {
        contacts: {
          add: ['ops@ta.example.org', 'ops@intermediate.example.org'],
        },
      },
    })
  })

  it('should fail to different default metadata policies', async () => {
    const leafEntityId = 'https://leaf.example.org'
    const intermediateEntityId = 'https://intermediate.example.org'
    const trustAnchorEntityId = 'https://trust.example.org'

    const { chainData: configurations } = await setupConfigurationChain(
      [
        { entityId: leafEntityId, authorityHints: [intermediateEntityId] },
        {
          entityId: intermediateEntityId,
          authorityHints: [trustAnchorEntityId],
          subordinates: [
            {
              entityId: leafEntityId,
              claims: {
                metadata_policy: {
                  openid_relying_party: {
                    contacts: {
                      default: ['ops@intermediate.example.org'],
                    },
                  },
                },
              },
            },
          ],
        },
        {
          entityId: trustAnchorEntityId,
          subordinates: [
            {
              entityId: intermediateEntityId,
              claims: {
                metadata_policy: {
                  openid_relying_party: {
                    contacts: {
                      default: ['ops@ta.example.org'],
                    },
                  },
                },
              },
            },
          ],
        },
      ],
      { signJwtCallback, mockEndpoints: true }
    )

    const statements = subordinateStatements(configurations)

    assert.throws(() => combineMetadataPolicies({ statements }))
  })

  it('should combine default metadata policies', async () => {
    const leafEntityId = 'https://leaf.example.org'
    const intermediateEntityId = 'https://intermediate.example.org'
    const trustAnchorEntityId = 'https://trust.example.org'

    const { chainData: configurations } = await setupConfigurationChain(
      [
        { entityId: leafEntityId, authorityHints: [intermediateEntityId] },
        {
          entityId: intermediateEntityId,
          authorityHints: [trustAnchorEntityId],
          subordinates: [
            {
              entityId: leafEntityId,
              claims: {
                metadata_policy: {
                  openid_relying_party: {
                    contacts: {
                      default: ['ops@contact.example.org'],
                    },
                  },
                },
              },
            },
          ],
        },
        {
          entityId: trustAnchorEntityId,
          subordinates: [
            {
              entityId: intermediateEntityId,
              claims: {
                metadata_policy: {
                  openid_relying_party: {
                    contacts: {
                      default: ['ops@contact.example.org'],
                    },
                  },
                },
              },
            },
          ],
        },
      ],
      { signJwtCallback, mockEndpoints: true }
    )

    const statements = subordinateStatements(configurations)

    const { mergedPolicy } = await combineMetadataPolicies({ statements })

    assert.deepStrictEqual(mergedPolicy, {
      openid_relying_party: {
        contacts: {
          default: ['ops@contact.example.org'],
        },
      },
    })
  })
})
