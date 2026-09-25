/**
 * An `@aws-sdk/client-kms` client adapts to `KmsClient` without a cast.
 *
 * This file is type-checked by `tsc --noEmit`; the adapter below fails the build if the SDK's request
 * fields widen back to `string`, which the AWS client's literal unions do not accept.
 */

import { GetPublicKeyCommand, KMSClient, SignCommand } from '@aws-sdk/client-kms';
import { describe, expect, it } from 'vitest';
import type { KmsClient } from '../src/l2/adapters/aws-kms';

function adapt(client: KMSClient): KmsClient {
  return {
    sign: (input) => client.send(new SignCommand(input)),
    getPublicKey: (input) => client.send(new GetPublicKeyCommand(input)),
  };
}

describe('the AWS KMS client', () => {
  it('adapts to KmsClient without a cast', () => {
    expect(typeof adapt(new KMSClient({ region: 'ap-northeast-1' })).sign).toBe('function');
  });
});
