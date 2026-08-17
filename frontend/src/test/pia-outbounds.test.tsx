import { screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import PiaOutbounds from '@/pages/xray/outbounds/PiaOutbounds';
import { renderWithProviders } from './test-utils';

describe('PiaOutbounds', () => {
  it('renders read-only PIA cards and manager action', () => {
    renderWithProviders(
      <PiaOutbounds
        piaOutbounds={[{ uid: 'e1', tag: 'pia-abcd1234', region: 'US East', server: 'useast1', status: 'ready' }]}
        onOpenManager={() => undefined}
      />,
    );
    expect(screen.getByText('pia-abcd1234')).toBeTruthy();
    expect(screen.getByText('US East')).toBeTruthy();
  });
});
