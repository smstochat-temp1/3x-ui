import { Button, Space, Table, Tag, Typography } from 'antd';
import { useTranslation } from 'react-i18next';

interface PiaRow {
  uid?: string;
  tag?: string;
  region?: string;
  server?: string;
  status?: string;
}

export default function PiaOutbounds({
  piaOutbounds,
  onOpenManager,
}: {
  piaOutbounds: unknown[];
  onOpenManager: () => void;
}) {
  const { t } = useTranslation();
  const rows = (piaOutbounds || []) as PiaRow[];
  if (rows.length === 0) return null;

  return (
    <Space orientation="vertical" size="small" style={{ width: '100%' }}>
      <Typography.Text type="secondary">{t('pages.xray.pia.fromTitle')}</Typography.Text>
      <Table
        size="small"
        rowKey={(r) => r.uid || r.tag || ''}
        pagination={false}
        dataSource={rows}
        columns={[
          { title: t('pages.xray.pia.colTag'), dataIndex: 'tag' },
          { title: t('pages.xray.pia.colRegion'), dataIndex: 'region' },
          { title: t('pages.xray.pia.colServer'), dataIndex: 'server' },
          {
            title: t('status'),
            dataIndex: 'status',
            render: (status: string) => <Tag>{status}</Tag>,
          },
          {
            title: t('pages.xray.pia.openManager'),
            render: () => (
              <Button type="link" size="small" onClick={onOpenManager}>
                {t('pages.xray.pia.openManager')}
              </Button>
            ),
          },
        ]}
      />
    </Space>
  );
}
