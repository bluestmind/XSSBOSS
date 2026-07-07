/**
 * Engine Log — adapted from the 21st.dev "Audit Log" component by @corr (id 25163):
 * its timeline row design (connector line, icon bubble, timestamp, tag chips),
 * rebuilt without the Radix context-menu / filter dependencies and themed to the console.
 */
import type { ReactNode } from 'react';
import { CheckCircle2, XCircle, AlertTriangle, Info, Terminal, Sparkles } from 'lucide-react';
import type { MonitorEvent } from '@/types/api';

const levelStyle: Record<string, { icon: ReactNode; bubble: string; chip: string }> = {
  success: { icon: <CheckCircle2 className="size-3.5" />, bubble: 'border-emerald-500/40 bg-emerald-500/15 text-emerald-300', chip: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300' },
  error:   { icon: <XCircle className="size-3.5" />,      bubble: 'border-rose-500/40 bg-rose-500/15 text-rose-300',       chip: 'border-rose-500/30 bg-rose-500/10 text-rose-300' },
  warning: { icon: <AlertTriangle className="size-3.5" />, bubble: 'border-amber-500/40 bg-amber-500/15 text-amber-300',    chip: 'border-amber-500/30 bg-amber-500/10 text-amber-300' },
  info:    { icon: <Info className="size-3.5" />,          bubble: 'border-cyan-500/40 bg-cyan-500/15 text-cyan-300',       chip: 'border-cyan-500/30 bg-cyan-500/10 text-cyan-300' },
  debug:   { icon: <Terminal className="size-3.5" />,      bubble: 'border-carbon-600 bg-carbon-800 text-carbon-400',       chip: 'border-carbon-600 bg-carbon-800/60 text-carbon-400' },
};
const fallbackStyle = { icon: <Sparkles className="size-3.5" />, bubble: 'border-brand-500/40 bg-brand-500/15 text-brand-300', chip: 'border-brand-500/30 bg-brand-500/10 text-brand-300' };

const formatTime = (value: string) => {
  if (!value) return '';
  try {
    const dateStr = value.endsWith('Z') || value.includes('+') ? value : value + 'Z';
    return new Date(dateStr).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true });
  } catch {
    return value;
  }
};

const EngineLog = ({ events }: { events: MonitorEvent[] }) => {
  if (events.length === 0) {
    return (
      <div className="rounded-xl border border-carbon-700/60 bg-carbon-950/30 px-4 py-10 text-center text-sm text-carbon-400">
        No engine decisions for this filter yet.
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-carbon-700/60 bg-carbon-950/30">
      {events.map((event, index) => {
        const style = levelStyle[event.level] || fallbackStyle;
        return (
          <div key={`${event.timestamp}-${index}`} className="relative flex gap-3 px-4 py-3">
            {index < events.length - 1 && (
              <div className="absolute left-[1.62rem] top-9 bottom-0 w-px bg-carbon-700/50" />
            )}
            <div className={`z-10 flex size-6 shrink-0 items-center justify-center rounded-full border ${style.bubble}`}>
              {style.icon}
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-sm font-medium text-carbon-100">{event.message}</div>
                <div className="font-mono text-[11px] text-carbon-500">{formatTime(event.timestamp)}</div>
              </div>
              {event.detail && (
                <div className="mt-1 text-xs leading-5 text-carbon-400">{event.detail}</div>
              )}
              <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px]">
                <span className="font-mono font-semibold uppercase tracking-wide text-brand-300">{event.phase}</span>
                <span className={`rounded-full border px-2 py-0.5 font-medium uppercase tracking-wide ${style.chip}`}>
                  {event.level}
                </span>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
};

export default EngineLog;
