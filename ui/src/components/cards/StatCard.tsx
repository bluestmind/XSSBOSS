/** Statistics tile — thin wrapper over the 21st.dev KPI Card, mapped to the app's color props. */
import { KpiCard } from '@/components/ui/kpi-card';

interface StatCardProps {
  label: string;
  value: string | number;
  icon?: string;
  color?: 'blue' | 'green' | 'yellow' | 'red' | 'purple' | 'orange';
  sub?: string;
}

const toneByColor = {
  blue: 'primary',
  green: 'success',
  yellow: 'warning',
  red: 'danger',
  purple: 'primary',
  orange: 'warning',
} as const;

const StatCard = ({ label, value, icon, color = 'blue', sub }: StatCardProps) => (
  <KpiCard
    label={label}
    value={value}
    caption={sub}
    tone={toneByColor[color]}
    size="md"
    icon={icon ? <span className="text-base leading-none">{icon}</span> : undefined}
  />
);

export default StatCard;
