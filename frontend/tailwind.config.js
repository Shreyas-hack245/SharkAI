/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        shark: {
          950: '#0a0e17',
          900: '#0f1520',
          800: '#151c2c',
          700: '#1a2332',
          600: '#243044',
          500: '#2d3a52',
          400: '#4a6080',
          300: '#6b8299',
          200: '#94a8be',
          100: '#c5d4e3',
          50: '#e8eef4',
          accent: '#00d4aa',
          danger: '#ff4757',
          warning: '#ffa502',
          info: '#3498db',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
