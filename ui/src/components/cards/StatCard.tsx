/** Statistics card component */
interface StatCardProps {
  label: string;
  value: string | number;
  icon?: string;
  color?: 'blue' | 'green' | 'yellow' | 'red' | 'purple' | 'orange';
  sub?: string;
}

const palette = {
  blue:   { bar: 'bg-blue-500',   icon: 'bg-blue-100 text-blue-600',   text: 'text-blue-700',   num: 'text-blue-900'   },
  green:  { bar: 'bg-green-500',  icon: 'bg-green-100 text-green-600', text: 'text-green-700',  num: 'text-green-900'  },
  yellow: { bar: 'bg-yellow-400', icon: 'bg-yellow-100 text-yellow-600',text: 'text-yellow-700', num: 'text-yellow-900' },
  red:    { bar: 'bg-red-500',    icon: 'bg-red-100 text-red-600',     text: 'text-red-700',    num: 'text-red-900'    },
  purple: { bar: 'bg-purple-500', icon: 'bg-purple-100 text-purple-600',text: 'text-purple-700', num: 'text-purple-900' },
  orange: { bar: 'bg-orange-500', icon: 'bg-orange-100 text-orange-600',text: 'text-orange-700', num: 'text-orange-900' },
};

const StatCard = ({ label, value, icon, color = 'blue', sub }: StatCardProps) => {
  const p = palette[color];
  return (
    <div className="relative bg-white rounded-xl border border-gray-100 shadow-sm overflow-hidden hover:shadow-md transition-shadow">
      <div className={`absolute top-0 left-0 h-full w-1 ${p.bar}`} />
      <div className="pl-5 pr-4 py-4 flex items-center justify-between gap-3">
        <div className="min-w-0">
          <p className={`text-xs font-semibold uppercase tracking-wider ${p.text} truncate`}>{label}</p>
          <p className={`text-3xl font-extrabold mt-1 ${p.num} tabular-nums`}>{value}</p>
          {sub && <p className="text-xs text-gray-400 mt-0.5 truncate">{sub}</p>}
        </div>
        {icon && (
          <div className={`flex-shrink-0 w-11 h-11 rounded-lg flex items-center justify-center text-xl ${p.icon}`}>
            {icon}
          </div>
        )}
      </div>
    </div>
  );
};

export default StatCard;
