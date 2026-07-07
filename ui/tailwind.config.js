/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['"IBM Plex Sans"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        display: ['"Space Grotesk"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      colors: {
        // Blue-black neutral ramp — the console canvas
        carbon: {
          950: '#070A11',
          900: '#0A0E17',
          850: '#0E1523',
          800: '#121B2C',
          750: '#172136',
          700: '#1E2A42',
          600: '#2A3854',
          500: '#3A4A6B',
          400: '#5D6E90',
          300: '#8695B3',
          200: '#B7C2D8',
          100: '#E8EDF8',
        },
        // Iris — primary "engine" accent / injection energy
        brand: {
          50:  '#F1EEFF',
          100: '#E3DDFF',
          200: '#C7BCFF',
          300: '#A99AFF',
          400: '#9385FF',
          500: '#7B68FF',
          600: '#6248F0',
          700: '#4E37C9',
          800: '#3B2A99',
          900: '#2A1E6E',
        },
        // Keep legacy semantic scales so existing components keep compiling
        primary: {
          50: '#f0f9ff', 100: '#e0f2fe', 200: '#bae6fd', 300: '#7dd3fc', 400: '#38bdf8',
          500: '#0ea5e9', 600: '#0284c7', 700: '#0369a1', 800: '#075985', 900: '#0c4a6e',
        },
        danger: {
          50: '#fef2f2', 100: '#fee2e2', 200: '#fecaca', 300: '#fca5a5', 400: '#f87171',
          500: '#ef4444', 600: '#dc2626', 700: '#b91c1c', 800: '#991b1b', 900: '#7f1d1d',
        },
        success: {
          50: '#f0fdf4', 100: '#dcfce7', 200: '#bbf7d0', 300: '#86efac', 400: '#4ade80',
          500: '#22c55e', 600: '#16a34a', 700: '#15803d', 800: '#166534', 900: '#14532d',
        },
        warning: {
          50: '#fffbeb', 100: '#fef3c7', 200: '#fde68a', 300: '#fcd34d', 400: '#fbbf24',
          500: '#f59e0b', 600: '#d97706', 700: '#b45309', 800: '#92400e', 900: '#78350f',
        },
      },
      boxShadow: {
        panel: '0 1px 0 0 rgba(255,255,255,0.03) inset, 0 24px 48px -28px rgba(0,0,0,0.9)',
        'glow-brand': '0 0 0 1px rgba(123,104,255,0.35), 0 12px 40px -12px rgba(123,104,255,0.55)',
        'glow-rose': '0 0 0 1px rgba(244,63,94,0.4), 0 12px 40px -14px rgba(244,63,94,0.5)',
        'glow-emerald': '0 0 0 1px rgba(16,185,129,0.35), 0 0 28px -8px rgba(16,185,129,0.55)',
        'glow-amber': '0 0 0 1px rgba(245,158,11,0.35), 0 0 26px -10px rgba(245,158,11,0.5)',
      },
      backgroundImage: {
        'brand-sheen': 'linear-gradient(110deg, transparent 20%, rgba(255,255,255,0.14) 42%, transparent 64%)',
      },
      keyframes: {
        'pulse-soft': { '0%,100%': { opacity: '1' }, '50%': { opacity: '0.4' } },
        blink: { '0%,100%': { opacity: '1' }, '50%': { opacity: '0' } },
        scan: { '0%': { transform: 'translateY(-120%)' }, '100%': { transform: 'translateY(320%)' } },
        sheen: { '0%': { backgroundPosition: '200% 0' }, '100%': { backgroundPosition: '-200% 0' } },
        rise: { '0%': { opacity: '0', transform: 'translateY(8px)' }, '100%': { opacity: '1', transform: 'translateY(0)' } },
        'spin-slow': { to: { transform: 'rotate(360deg)' } },
      },
      animation: {
        'pulse-soft': 'pulse-soft 2.4s ease-in-out infinite',
        blink: 'blink 1.1s step-end infinite',
        scan: 'scan 3.4s cubic-bezier(0.4,0,0.6,1) infinite',
        sheen: 'sheen 2.8s linear infinite',
        rise: 'rise 0.45s ease-out both',
        'spin-slow': 'spin-slow 8s linear infinite',
      },
    },
  },
  plugins: [],
}
