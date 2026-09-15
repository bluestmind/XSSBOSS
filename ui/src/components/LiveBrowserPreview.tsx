import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { Eye, Maximize2, Minimize2, RefreshCw, Radio, Globe, Terminal, Pause, Play } from 'lucide-react';

interface LiveScreenMetadata {
  url?: string;
  title?: string;
  test_case_id?: number;
  param_name?: string;
  payload?: string;
  engine?: string;
  oracle_hit?: boolean;
  timestamp?: string;
}

interface LiveScreenResponse {
  available: boolean;
  image_url: string | null;
  metadata: LiveScreenMetadata;
}

interface LiveBrowserPreviewProps {
  className?: string;
  defaultExpanded?: boolean;
  pollingIntervalMs?: number;
}

export const LiveBrowserPreview: React.FC<LiveBrowserPreviewProps> = ({
  className = '',
  pollingIntervalMs = 1500,
}) => {
  const [data, setData] = useState<LiveScreenResponse | null>(null);
  const [isPolling, setIsPolling] = useState(true);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [imgError, setImgError] = useState(false);
  const timerRef = useRef<number | null>(null);

  const fetchLiveFrame = async () => {
    try {
      const res = await axios.get<LiveScreenResponse>('/api/v1/scans/live-screen');
      if (res.data) {
        setData(res.data);
        setImgError(false);
      }
    } catch {
      // Ignored
    }
  };

  useEffect(() => {
    fetchLiveFrame();
    if (!isPolling) return;

    timerRef.current = window.setInterval(fetchLiveFrame, pollingIntervalMs);
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isPolling, pollingIntervalMs]);

  const meta = data?.metadata || {};
  const hasLiveImage = data?.available && data.image_url && !imgError;

  return (
    <>
      <div className={`overflow-hidden rounded-2xl border border-carbon-700/80 bg-carbon-900/90 shadow-2xl backdrop-blur-xl ${className}`}>
        {/* Top HUD Header */}
        <div className="flex flex-wrap items-center justify-between border-b border-carbon-800 bg-carbon-950/80 px-4 py-3">
          <div className="flex items-center gap-3">
            <div className="relative flex items-center justify-center">
              <span className="absolute h-3 w-3 animate-ping rounded-full bg-emerald-400 opacity-75" />
              <span className="relative h-2.5 w-2.5 rounded-full bg-emerald-500 shadow-glow-emerald" />
            </div>
            <div className="flex items-center gap-2">
              <Eye className="h-4 w-4 text-brand-400" />
              <span className="font-display text-sm font-bold tracking-wide text-carbon-100 uppercase">
                Live Browser Vision
              </span>
            </div>
            {meta.engine && (
              <span className="rounded-md border border-brand-500/30 bg-brand-500/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-brand-300">
                {meta.engine}
              </span>
            )}
            {meta.test_case_id && (
              <span className="rounded-md border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 font-mono text-[10px] font-bold text-amber-300">
                Case #{meta.test_case_id}
              </span>
            )}
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setIsPolling(!isPolling)}
              title={isPolling ? 'Pause Live Stream' : 'Resume Live Stream'}
              className="flex items-center gap-1 rounded-lg border border-carbon-700 bg-carbon-800/80 px-2.5 py-1 text-xs font-medium text-carbon-300 transition hover:border-carbon-600 hover:text-carbon-100"
            >
              {isPolling ? <Pause className="h-3.5 w-3.5 text-amber-400" /> : <Play className="h-3.5 w-3.5 text-emerald-400" />}
              <span>{isPolling ? 'Live' : 'Paused'}</span>
            </button>
            <button
              type="button"
              onClick={fetchLiveFrame}
              title="Refresh Current Frame"
              className="rounded-lg border border-carbon-700 bg-carbon-800/80 p-1.5 text-carbon-300 transition hover:border-carbon-600 hover:text-carbon-100"
            >
              <RefreshCw className="h-3.5 w-3.5" />
            </button>
            <button
              type="button"
              onClick={() => setIsFullscreen(true)}
              disabled={!hasLiveImage}
              title="Fullscreen Browser Preview"
              className="rounded-lg border border-carbon-700 bg-carbon-800/80 p-1.5 text-carbon-300 transition hover:border-carbon-600 hover:text-carbon-100 disabled:opacity-40"
            >
              <Maximize2 className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>

        {/* URL Bar */}
        <div className="flex items-center gap-2 border-b border-carbon-800/60 bg-carbon-950/40 px-4 py-2 font-mono text-xs text-carbon-400">
          <Globe className="h-3.5 w-3.5 flex-shrink-0 text-carbon-500" />
          <span className="truncate text-carbon-200">
            {meta.url || 'http://127.0.0.1:8000 (Idle / Standby)'}
          </span>
          {meta.param_name && (
            <span className="ml-auto flex-shrink-0 rounded bg-carbon-800 px-2 py-0.5 text-[10px] text-fuchsia-300">
              Param: {meta.param_name}
            </span>
          )}
        </div>

        {/* Viewport Frame */}
        <div className="relative flex aspect-video w-full items-center justify-center overflow-hidden bg-black/60">
          {hasLiveImage ? (
            <div className="group relative h-full w-full cursor-pointer" onClick={() => setIsFullscreen(true)}>
              <img
                src={data?.image_url || ''}
                alt="Live Headless Browser Preview"
                onError={() => setImgError(true)}
                className="h-full w-full object-contain transition-transform duration-300 group-hover:scale-[1.01]"
              />
              <div className="absolute inset-0 bg-gradient-to-t from-black/80 via-transparent to-transparent opacity-0 transition-opacity duration-200 group-hover:opacity-100 flex items-end p-4">
                <span className="flex items-center gap-1.5 rounded-lg bg-black/80 px-3 py-1.5 text-xs font-semibold text-carbon-100 backdrop-blur-md">
                  <Maximize2 className="h-3.5 w-3.5 text-brand-400" /> Click to enlarge browser frame
                </span>
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center p-8 text-center">
              <div className="relative mb-3 flex h-16 w-16 items-center justify-center rounded-2xl border border-brand-500/20 bg-brand-500/5">
                <Terminal className="h-8 w-8 text-brand-400 animate-pulse" />
              </div>
              <p className="font-display text-sm font-semibold text-carbon-200">
                Awaiting active browser execution frame...
              </p>
              <p className="mt-1 max-w-sm font-mono text-xs text-carbon-500">
                When an experiment runs test cases via Undetected Chrome, live rendered DOM screenshots will appear here in real-time.
              </p>
            </div>
          )}

          {/* Bottom telemetry overlay */}
          {meta.payload && (
            <div className="absolute bottom-2 left-2 right-2 flex items-center justify-between rounded-xl border border-carbon-700/80 bg-carbon-900/90 px-3 py-1.5 backdrop-blur-md">
              <div className="flex items-center gap-2 truncate">
                <span className="font-mono text-[10px] uppercase font-bold text-brand-400">Payload:</span>
                <code className="truncate font-mono text-xs text-carbon-200">{meta.payload}</code>
              </div>
              {meta.oracle_hit && (
                <span className="rounded bg-rose-500/20 px-2 py-0.5 text-[10px] font-bold text-rose-300 uppercase">
                  Execution Hit
                </span>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Fullscreen Zoom Modal */}
      {isFullscreen && (
        <div
          className="fixed inset-0 z-50 flex flex-col items-center justify-center bg-black/90 p-4 backdrop-blur-xl"
          onClick={() => setIsFullscreen(false)}
        >
          <div
            className="relative flex max-h-[95vh] max-w-[95vw] flex-col overflow-hidden rounded-2xl border border-carbon-700 bg-carbon-900 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-carbon-800 bg-carbon-950 px-4 py-3">
              <div className="flex items-center gap-3">
                <Radio className="h-4 w-4 text-emerald-400 animate-pulse" />
                <span className="font-display text-sm font-bold text-carbon-100">
                  Full Resolution Browser Render
                </span>
                <span className="font-mono text-xs text-carbon-400 truncate max-w-lg">{meta.url}</span>
              </div>
              <button
                type="button"
                onClick={() => setIsFullscreen(false)}
                className="rounded-lg border border-carbon-700 p-1.5 text-carbon-400 hover:text-carbon-100"
              >
                <Minimize2 className="h-4 w-4" />
              </button>
            </div>
            <div className="overflow-auto p-2">
              <img
                src={data?.image_url || ''}
                alt="Fullscreen Rendered Browser"
                className="max-h-[80vh] w-auto object-contain rounded-lg"
              />
            </div>
          </div>
        </div>
      )}
    </>
  );
};

export default LiveBrowserPreview;
