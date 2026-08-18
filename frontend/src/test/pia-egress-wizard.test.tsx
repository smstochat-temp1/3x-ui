import { describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/react';

import PiaManager, { EgressWizard } from '@/pages/xray/overrides/pia/PiaManager';
import { HttpUtil, Msg } from '@/utils';
import { renderWithProviders } from './test-utils';

const PROFILE = {
  uid: 'profile-1',
  name: 'Primary PIA account',
};

const REGIONS = [
  { id: 'us-east', name: 'US East', countryCode: 'US', serverCount: 2 },
  { id: 'us-west', name: 'US West', countryCode: 'US', serverCount: 1 },
  { id: 'de-berlin', name: 'Berlin', countryCode: 'DE', serverCount: 1 },
];

const SERVERS: Record<string, Array<{ hostname: string; ip: string }>> = {
  'us-east': [
    { hostname: 'useast1.example', ip: '198.51.100.10' },
    { hostname: 'useast2.example', ip: '198.51.100.20' },
  ],
  'us-west': [{ hostname: 'uswest1.example', ip: '198.51.100.30' }],
  'de-berlin': [{ hostname: 'berlin1.example', ip: '203.0.113.10' }],
};

function renderWizard(onCreated = vi.fn()) {
  return {
    onCreated,
    ...renderWithProviders(
      <EgressWizard open profiles={[PROFILE]} onClose={vi.fn()} onCreated={onCreated} />,
    ),
  };
}

function visibleOptions(): HTMLElement[] {
  return Array.from(
    document.querySelectorAll<HTMLElement>(
      '.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option',
    ),
  );
}

async function chooseOption(testId: string, labelPart: string) {
  const node = screen.getByTestId(testId);
  const select = node.closest('.ant-select') ?? node;
  const selector = select.querySelector('.ant-select-selector') ?? select;
  fireEvent.mouseDown(selector);
  await waitFor(() => expect(visibleOptions().length).toBeGreaterThan(0));
  const option = visibleOptions().find((item) => (item.getAttribute('title') ?? item.textContent ?? '').includes(labelPart));
  if (!option) throw new Error(`Missing option containing ${labelPart}`);
  fireEvent.click(option);
}

function next() {
  fireEvent.click(screen.getByRole('button', { name: 'Next' }));
}

describe('PIA egress wizard', () => {
  it('keeps the manager available while encryption-dependent creation is disabled', async () => {
    vi.mocked(HttpUtil.get).mockImplementation(async (url: string) => {
      if (url === '/panel/api/pia/status') {
        return new Msg(true, '', { secretboxReady: false, encryptionMode: 'off' });
      }
      if (url === '/panel/api/pia/profiles') return new Msg(true, '', []);
      if (url === '/panel/api/pia/egresses') return new Msg(true, '', []);
      if (url === '/panel/api/pia/catalog/status') {
        return new Msg(true, '', { fresh: true, regionCount: 3, serverCount: 4 });
      }
      return new Msg(false, `Unexpected GET ${url}`, null);
    });

    renderWithProviders(<PiaManager open onClose={vi.fn()} />);
    await waitFor(() => expect(screen.getByText(/PIA needs NODE_TOKEN_ENCRYPTION/)).toBeTruthy());
    expect((screen.getByRole('button', { name: 'Add outbound' }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole('button', { name: 'Add profile' }) as HTMLButtonElement).disabled).toBe(false);
    expect((screen.getByRole('button', { name: 'Refresh server list' }) as HTMLButtonElement).disabled).toBe(false);
  });

  it('filters regions by country, resets dependent choices, preselects a server, and provisions the reviewed endpoint', async () => {
    vi.mocked(HttpUtil.get).mockImplementation(async (url: string) => {
      if (url === '/panel/api/pia/catalog/regions') return new Msg(true, '', REGIONS);
      const match = url.match(/\/catalog\/regions\/([^/]+)\/servers$/);
      if (match) return new Msg(true, '', SERVERS[match[1]] ?? []);
      return new Msg(false, `Unexpected GET ${url}`, null);
    });
    vi.mocked(HttpUtil.post).mockImplementation(async (url: string, body?: unknown) => {
      if (url === '/panel/api/pia/egresses') {
        return new Msg(true, '', {
          uid: 'egress-1',
          name: 'Berlin',
          outboundTag: 'pia-abcd1234',
          ...(body as object),
        });
      }
      if (url === '/panel/api/pia/egresses/egress-1/provision') {
        return new Msg(true, '', {
          uid: 'egress-1',
          name: 'Berlin',
          outboundTag: 'pia-abcd1234',
          status: 'ready',
        });
      }
      return new Msg(false, `Unexpected POST ${url}`, null);
    });

    const { onCreated } = renderWizard();
    await chooseOption('pia-profile-select', PROFILE.name);
    next();

    await chooseOption('pia-country-select', 'United States (US)');
    next();
    await waitFor(() => expect(screen.getByTestId('pia-region-select')).toBeTruthy());
    await chooseOption('pia-region-select', 'US East (us-east)');

    fireEvent.click(screen.getByRole('button', { name: 'Back' }));
    await chooseOption('pia-country-select', 'Germany (DE)');
    next();
    await waitFor(() => expect(screen.getByTestId('pia-region-select').textContent).not.toContain('US East'));
    await chooseOption('pia-region-select', 'Berlin (de-berlin)');
    next();

    await waitFor(() => expect(screen.getByTestId('pia-server-select').textContent).toContain('berlin1.example'));
    next();
    next();

    expect(screen.getByText(/Country: .*Germany \(DE\)/)).toBeTruthy();
    expect(screen.getByText('Region: Berlin (de-berlin)')).toBeTruthy();
    expect(screen.getByText('Server: berlin1.example (203.0.113.10)')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Provision' }));

    await waitFor(() => expect(onCreated).toHaveBeenCalledOnce());
    const createCall = vi.mocked(HttpUtil.post).mock.calls.find(([url]) => url === '/panel/api/pia/egresses');
    expect(createCall?.[1]).toMatchObject({
      profileUid: PROFILE.uid,
      regionId: 'de-berlin',
      serverHostname: 'berlin1.example',
      ipv6Policy: 'block',
    });
  });

  it('does not allow the server step to advance when a region has no endpoints', async () => {
    vi.mocked(HttpUtil.get).mockImplementation(async (url: string) => {
      if (url === '/panel/api/pia/catalog/regions') return new Msg(true, '', [REGIONS[0]]);
      if (url.includes('/servers')) return new Msg(true, '', []);
      return new Msg(false, `Unexpected GET ${url}`, null);
    });

    renderWizard();
    await chooseOption('pia-profile-select', PROFILE.name);
    next();
    await chooseOption('pia-country-select', 'United States (US)');
    next();
    await chooseOption('pia-region-select', 'US East (us-east)');
    next();

    await waitFor(() => expect((screen.getByRole('button', { name: 'Next' }) as HTMLButtonElement).disabled).toBe(true));
    expect(screen.getByTestId('pia-server-select').textContent).not.toContain('example');
  });
});
