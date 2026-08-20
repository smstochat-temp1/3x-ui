import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Alert,
  Button,
  Drawer,
  Form,
  Input,
  InputNumber,
  Modal,
  Select,
  Space,
  Steps,
  Table,
  Tag,
  Typography,
} from 'antd';

import { keys } from '@/api/queryKeys';
import { countryFlag, countryName } from '../../outbounds/outbounds-tab-helpers';
import {
  piaDelete,
  piaGet,
  piaPost,
  piaSchemas,
  type PiaCatalogStatus,
  type PiaDependency,
  type PiaEgress,
  type PiaProfile,
  type PiaRegion,
  type PiaServer,
  type PiaStatus,
} from './pia-api';

const { Text } = Typography;

interface PiaManagerProps {
  open: boolean;
  onClose: () => void;
  onChanged?: () => void;
}

export default function PiaManager({ open, onClose, onChanged }: PiaManagerProps) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [error, setError] = useState('');
  const [wizardOpen, setWizardOpen] = useState(false);
  const [authProfileUid, setAuthProfileUid] = useState<string>();
  const [authUsername, setAuthUsername] = useState('');
  const [authPassword, setAuthPassword] = useState('');
  const [authSubmitting, setAuthSubmitting] = useState(false);

  const statusQuery = useQuery({
    queryKey: keys.pia.status(),
    queryFn: async () => {
      const msg = await piaGet<PiaStatus>('/panel/api/pia/status', piaSchemas.status);
      if (!msg.success || !msg.obj) throw new Error(msg.msg || 'status');
      return msg.obj;
    },
    enabled: open,
  });

  const profilesQuery = useQuery({
    queryKey: keys.pia.profiles(),
    queryFn: async () => {
      const msg = await piaGet<PiaProfile[]>('/panel/api/pia/profiles', piaSchemas.profiles);
      if (!msg.success) throw new Error(msg.msg);
      return Array.isArray(msg.obj) ? msg.obj : [];
    },
    enabled: open,
  });
  const egressesQuery = useQuery({
    queryKey: keys.pia.egresses(),
    queryFn: async () => {
      const msg = await piaGet<PiaEgress[]>('/panel/api/pia/egresses', piaSchemas.egresses);
      if (!msg.success) throw new Error(msg.msg);
      return Array.isArray(msg.obj) ? msg.obj : [];
    },
    enabled: open,
  });
  const catalogQuery = useQuery({
    queryKey: keys.pia.catalog(),
    queryFn: async () => {
      const msg = await piaGet<PiaCatalogStatus>('/panel/api/pia/catalog/status', piaSchemas.catalog);
      if (!msg.success) throw new Error(msg.msg);
      return msg.obj;
    },
    enabled: open,
  });

  const status = statusQuery.data ?? null;
  const profiles = profilesQuery.data ?? [];
  const egresses = egressesQuery.data ?? [];
  const catalog = catalogQuery.data ?? null;

  async function reload() {
    await queryClient.invalidateQueries({ queryKey: keys.pia.root() });
  }

  useEffect(() => {
    if (statusQuery.error) setError((statusQuery.error as Error).message);
    else if (profilesQuery.error) setError((profilesQuery.error as Error).message);
    else if (egressesQuery.error) setError((egressesQuery.error as Error).message);
  }, [statusQuery.error, profilesQuery.error, egressesQuery.error]);

  async function addProfile() {
    const name = window.prompt(t('pages.xray.pia.profileName'));
    if (!name) return;
    const msg = await piaPost<PiaProfile>('/panel/api/pia/profiles', { name }, piaSchemas.profile);
    if (!msg.success) {
      setError(msg.msg);
      return;
    }
    setError('');
    await reload();
  }

  async function authenticate() {
    if (!authProfileUid || !authUsername.trim() || !authPassword) return;
    setAuthSubmitting(true);
    const msg = await piaPost(`/panel/api/pia/profiles/${authProfileUid}/authenticate`, {
      username: authUsername.trim(),
      password: authPassword,
    });
    setAuthSubmitting(false);
    setError(msg.success ? '' : msg.msg);
    if (msg.success) {
      setAuthProfileUid(undefined);
      setAuthUsername('');
      setAuthPassword('');
    }
    await reload();
  }

  async function refreshCatalog() {
    const msg = await piaPost('/panel/api/pia/catalog/refresh', undefined, piaSchemas.catalog);
    setError(msg.success ? '' : msg.msg);
    await reload();
  }

  async function provision(uid: string) {
    const msg = await piaPost(`/panel/api/pia/egresses/${uid}/provision`, undefined, piaSchemas.egress);
    setError(msg.success ? '' : msg.msg);
    await reload();
    onChanged?.();
  }

  async function rotateKey(uid: string) {
    const msg = await piaPost(`/panel/api/pia/egresses/${uid}/rotate-key`, undefined, piaSchemas.egress);
    setError(msg.success ? '' : msg.msg);
    await reload();
    onChanged?.();
  }

  async function testEgress(uid: string) {
    const msg = await piaPost(`/panel/api/pia/egresses/${uid}/test`, { mode: 'http' });
    setError(msg.success ? '' : msg.msg);
  }

  async function disableOrDelete(uid: string, kind: 'disable' | 'delete') {
    const depsMsg = await piaGet<PiaDependency[]>(`/panel/api/pia/egresses/${uid}/dependencies`, piaSchemas.dependencies);
    const deps = depsMsg.success && Array.isArray(depsMsg.obj) ? depsMsg.obj : [];
    let replacementTag = '';
    let deleteRules = false;
    if (deps.length > 0) {
      const ok = await new Promise<boolean>((resolve) => {
        const modal = Modal.confirm({
          title: t('pages.xray.pia.dependencyTitle'),
          content: (
            <Space orientation="vertical">
              <Text>{t('pages.xray.pia.dependencyHint')}</Text>
              <ul>
                {deps.map((d) => (
                  <li key={`${d.kind}-${d.label}`}>{`${d.kind}: ${d.label}`}</li>
                ))}
              </ul>
              <Input
                placeholder={t('pages.xray.pia.replacementTag')}
                onChange={(e) => {
                  replacementTag = e.target.value.trim();
                  modal.update({
                    okText: t(replacementTag ? 'update' : 'pages.xray.pia.deleteRules'),
                  });
                }}
              />
            </Space>
          ),
          okText: t('pages.xray.pia.deleteRules'),
          cancelText: t('cancel'),
          onOk: () => {
            if (!replacementTag) deleteRules = true;
            resolve(true);
          },
          onCancel: () => resolve(false),
        });
      });
      if (!ok) return;
    }
    const q = new URLSearchParams();
    if (replacementTag) q.set('replacementTag', replacementTag);
    if (deleteRules) q.set('deleteRules', 'true');
    const qs = q.toString() ? `?${q.toString()}` : '';
    const msg =
      kind === 'delete'
        ? await piaDelete(`/panel/api/pia/egresses/${uid}${qs}`)
        : await piaPost(`/panel/api/pia/egresses/${uid}/disable`, { replacementTag, deleteRules });
    setError(msg.success ? '' : msg.msg);
    await reload();
    onChanged?.();
  }

  return (
    <Drawer
      title={t('pages.xray.pia.title')}
      open={open}
      onClose={onClose}
      width={920}
      destroyOnHidden
    >
      <Space orientation="vertical" size="large" style={{ width: '100%' }}>
        {status && !status.secretboxReady && (
          <Alert type="error" showIcon message={t('pages.xray.pia.encryptionHint')} />
        )}
        {error && <Alert type="error" showIcon message={error} />}
        <Space wrap>
          <Button onClick={() => void reload()}>{t('refresh')}</Button>
          <Button onClick={() => void refreshCatalog()}>{t('pages.xray.pia.refreshCatalog')}</Button>
          <Button onClick={() => void addProfile()}>{t('pages.xray.pia.addProfile')}</Button>
          <Button type="primary" onClick={() => setWizardOpen(true)} disabled={!status?.secretboxReady}>
            {t('pages.xray.pia.addEgress')}
          </Button>
        </Space>
        <Text type="secondary">
          {t('pages.xray.pia.catalogStatus', {
            fresh: catalog?.fresh ? t('pages.xray.pia.fresh') : t('pages.xray.pia.stale'),
            regions: catalog?.regionCount ?? 0,
            servers: catalog?.serverCount ?? 0,
          })}
        </Text>
        <Table
          size="small"
          rowKey="uid"
          pagination={false}
          dataSource={profiles}
          columns={[
            { title: t('pages.xray.pia.profileName'), dataIndex: 'name' },
            { title: t('pages.xray.pia.accountHint'), dataIndex: 'accountHint' },
            { title: t('status'), dataIndex: 'authStatus', render: (v: string) => <Tag>{v}</Tag> },
            {
              title: t('pages.xray.pia.signIn'),
              render: (_: unknown, row: PiaProfile) => (
                <Button size="small" disabled={!status?.secretboxReady} onClick={() => setAuthProfileUid(row.uid)}>
                  {t('pages.xray.pia.signIn')}
                </Button>
              ),
            },
          ]}
        />
        <Table
          size="small"
          rowKey="uid"
          pagination={false}
          dataSource={egresses}
          columns={[
            { title: t('pages.xray.pia.colTag'), dataIndex: 'outboundTag' },
            { title: t('pages.xray.pia.colName'), dataIndex: 'name' },
            { title: t('pages.xray.pia.colRegion'), dataIndex: 'regionName' },
            { title: t('status'), dataIndex: 'status', render: (v: string) => <Tag>{v}</Tag> },
            {
              title: t('more'),
              render: (_: unknown, row: PiaEgress) => (
                <Space wrap>
                  <Button size="small" disabled={!status?.secretboxReady} onClick={() => void provision(row.uid)}>
                    {t('pages.xray.pia.provision')}
                  </Button>
                  <Button size="small" disabled={!status?.secretboxReady} onClick={() => void rotateKey(row.uid)}>
                    {t('pages.xray.pia.rotateKey')}
                  </Button>
                  <Button size="small" disabled={!status?.secretboxReady} onClick={() => void testEgress(row.uid)}>
                    {t('pages.xray.pia.test')}
                  </Button>
                  <Button size="small" danger onClick={() => void disableOrDelete(row.uid, 'delete')}>
                    {t('delete')}
                  </Button>
                </Space>
              ),
            },
          ]}
        />
        <Alert type="info" showIcon message={t('pages.xray.pia.ipv6Warning')} />
      </Space>
      <EgressWizard
        open={wizardOpen}
        profiles={profiles}
        onClose={() => setWizardOpen(false)}
        onCreated={async () => {
          setWizardOpen(false);
          await reload();
          onChanged?.();
        }}
      />
      <Modal
        open={Boolean(authProfileUid)}
        title={t('pages.xray.pia.signIn')}
        okText={t('pages.xray.pia.signIn')}
        cancelText={t('cancel')}
        confirmLoading={authSubmitting}
        okButtonProps={{ disabled: !authUsername.trim() || !authPassword }}
        onOk={() => void authenticate()}
        onCancel={() => {
          setAuthProfileUid(undefined);
          setAuthUsername('');
          setAuthPassword('');
        }}
        destroyOnHidden
      >
        <Space orientation="vertical" style={{ width: '100%' }}>
          <Input
            value={authUsername}
            placeholder={t('pages.xray.pia.username')}
            autoComplete="username"
            onChange={(event) => setAuthUsername(event.target.value)}
          />
          <Input.Password
            value={authPassword}
            placeholder={t('pages.xray.pia.password')}
            autoComplete="current-password"
            onChange={(event) => setAuthPassword(event.target.value)}
          />
        </Space>
      </Modal>
    </Drawer>
  );
}

export function EgressWizard({
  open,
  profiles,
  onClose,
  onCreated,
}: {
  open: boolean;
  profiles: PiaProfile[];
  onClose: () => void;
  onCreated: () => void;
}) {
  const { t, i18n } = useTranslation();
  const [step, setStep] = useState(0);
  const [profileUid, setProfileUid] = useState<string>();
  const [countryCode, setCountryCode] = useState<string>();
  const [regionId, setRegionId] = useState<string>();
  const [hostname, setHostname] = useState<string>();
  const [name, setName] = useState('');
  const [error, setError] = useState('');

  const regionsQuery = useQuery({
    queryKey: keys.pia.regions(),
    queryFn: async () => {
      const msg = await piaGet<PiaRegion[]>('/panel/api/pia/catalog/regions', piaSchemas.regions);
      if (!msg.success) throw new Error(msg.msg);
      return Array.isArray(msg.obj) ? msg.obj : [];
    },
    enabled: open,
  });
  const serversQuery = useQuery({
    queryKey: keys.pia.servers(regionId || ''),
    queryFn: async () => {
      const msg = await piaGet<PiaServer[]>(`/panel/api/pia/catalog/regions/${regionId}/servers`, piaSchemas.servers);
      if (!msg.success) throw new Error(msg.msg);
      return Array.isArray(msg.obj) ? msg.obj : [];
    },
    enabled: open && Boolean(regionId),
  });
  const regions = useMemo(() => regionsQuery.data ?? [], [regionsQuery.data]);
  const servers = useMemo(() => serversQuery.data ?? [], [serversQuery.data]);
  const countries = useMemo(() => {
    const codes = [...new Set(regions.map((region) => region.countryCode.trim().toUpperCase()))];
    return codes
      .filter((code) => /^[A-Z]{2}$/.test(code))
      .map((code) => {
        const name = countryName(code, i18n.resolvedLanguage || i18n.language);
        const flag = countryFlag(code);
        return { value: code, name, label: `${flag ? `${flag} ` : ''}${name} (${code})` };
      })
      .sort((a, b) => a.name.localeCompare(b.name, i18n.resolvedLanguage || i18n.language));
  }, [i18n.language, i18n.resolvedLanguage, regions]);
  const filteredRegions = useMemo(
    () => regions.filter((region) => region.countryCode.toUpperCase() === countryCode),
    [countryCode, regions],
  );
  const selectedCountry = countries.find((country) => country.value === countryCode);
  const selectedRegion = regions.find((region) => region.id === regionId);
  const selectedServer = servers.find((server) => server.hostname === hostname);

  useEffect(() => {
    if (!open) return;
    setStep(0);
    setError('');
    setProfileUid(undefined);
    setCountryCode(undefined);
    setRegionId(undefined);
    setHostname(undefined);
    setName('');
  }, [open]);

  useEffect(() => {
    const queryError = regionsQuery.error ?? serversQuery.error;
    if (queryError) setError((queryError as Error).message);
  }, [regionsQuery.error, serversQuery.error]);

  useEffect(() => {
    if (!regionId || serversQuery.isFetching) return;
    if (servers.length === 0) {
      setHostname(undefined);
      return;
    }
    if (!servers.some((server) => server.hostname === hostname)) {
      setHostname(servers[0].hostname);
    }
  }, [hostname, regionId, servers, serversQuery.isFetching]);

  async function finish() {
    if (!profileUid || !countryCode || !regionId || !hostname) return;
    const created = await piaPost<PiaEgress>('/panel/api/pia/egresses', {
      profileUid,
      regionId,
      serverHostname: hostname,
      name,
      ipv6Policy: 'block',
    }, piaSchemas.egress);
    if (!created.success || !created.obj?.uid) {
      setError(created.msg);
      return;
    }
    const provisioned = await piaPost(`/panel/api/pia/egresses/${created.obj.uid}/provision`, undefined, piaSchemas.egress);
    if (!provisioned.success) {
      setError(provisioned.msg);
      return;
    }
    onCreated();
  }

  function canNext() {
    if (step === 0) return Boolean(profileUid);
    if (step === 1) return Boolean(countryCode);
    if (step === 2) return Boolean(regionId);
    if (step === 3) return Boolean(hostname) && !serversQuery.isFetching;
    return true;
  }

  return (
    <Modal open={open} onCancel={onClose} footer={null} title={t('pages.xray.pia.wizardTitle')} width={640} destroyOnHidden>
      <Space orientation="vertical" style={{ width: '100%' }} size="middle">
        <Steps
          current={step}
          size="small"
          items={[
            { title: t('pages.xray.pia.stepProfile') },
            { title: t('pages.xray.pia.stepCountry') },
            { title: t('pages.xray.pia.stepRegion') },
            { title: t('pages.xray.pia.stepServer') },
            { title: t('pages.xray.pia.stepOptions') },
            { title: t('pages.xray.pia.stepReview') },
          ]}
        />
        {error && <Alert type="error" showIcon message={error} />}
        {step === 0 && (
          <Select
            data-testid="pia-profile-select"
            style={{ width: '100%' }}
            placeholder={t('pages.xray.pia.stepProfile')}
            value={profileUid}
            onChange={setProfileUid}
            options={profiles.map((p) => ({ value: p.uid, label: p.name }))}
          />
        )}
        {step === 1 && (
          <Select
            data-testid="pia-country-select"
            style={{ width: '100%' }}
            showSearch={{ optionFilterProp: 'label' }}
            placeholder={t('pages.xray.pia.stepCountry')}
            value={countryCode}
            onChange={(code) => {
              setCountryCode(code);
              setRegionId(undefined);
              setHostname(undefined);
            }}
            options={countries}
          />
        )}
        {step === 2 && (
          <Select
            data-testid="pia-region-select"
            style={{ width: '100%' }}
            showSearch={{ optionFilterProp: 'label' }}
            placeholder={t('pages.xray.pia.stepRegion')}
            value={regionId}
            onChange={(id) => {
              setRegionId(id);
              setHostname(undefined);
            }}
            options={filteredRegions.map((region) => ({
              value: region.id,
              label: `${region.name} (${region.id}) · ${region.serverCount ?? 0}`,
            }))}
          />
        )}
        {step === 3 && (
          <Select
            data-testid="pia-server-select"
            style={{ width: '100%' }}
            showSearch={{ optionFilterProp: 'label' }}
            loading={serversQuery.isFetching}
            placeholder={t('pages.xray.pia.stepServer')}
            value={hostname}
            onChange={setHostname}
            options={servers.map((s) => ({ value: s.hostname, label: `${s.hostname} (${s.ip})` }))}
          />
        )}
        {step === 4 && (
          <Form layout="vertical">
            <Form.Item label={t('pages.xray.pia.colName')}>
              <Input value={name} onChange={(e) => setName(e.target.value)} />
            </Form.Item>
            <Form.Item label={t('pages.xray.pia.mtu')}>
              <InputNumber value={1420} disabled />
            </Form.Item>
            <Alert type="warning" showIcon message={t('pages.xray.pia.ipv6Warning')} />
          </Form>
        )}
        {step === 5 && (
          <Space orientation="vertical">
            <Text>{`${t('pages.xray.pia.stepProfile')}: ${profiles.find((p) => p.uid === profileUid)?.name || ''}`}</Text>
            <Text>{`${t('pages.xray.pia.stepCountry')}: ${selectedCountry?.label || countryCode || ''}`}</Text>
            <Text>{`${t('pages.xray.pia.stepRegion')}: ${selectedRegion ? `${selectedRegion.name} (${selectedRegion.id})` : ''}`}</Text>
            <Text>{`${t('pages.xray.pia.stepServer')}: ${selectedServer ? `${selectedServer.hostname} (${selectedServer.ip})` : ''}`}</Text>
          </Space>
        )}
        <Space>
          <Button disabled={step === 0} onClick={() => setStep((s) => s - 1)}>
            {t('pages.xray.pia.back')}
          </Button>
          {step < 5 ? (
            <Button type="primary" disabled={!canNext()} onClick={() => setStep((s) => s + 1)}>
              {t('pages.xray.pia.next')}
            </Button>
          ) : (
            <Button type="primary" onClick={() => void finish()}>
              {t('pages.xray.pia.provision')}
            </Button>
          )}
        </Space>
      </Space>
    </Modal>
  );
}
