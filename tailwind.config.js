/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./pages/**/*.{js,ts,jsx,tsx,mdx}', './components/**/*.{js,ts,jsx,tsx,mdx}', './app/**/*.{js,ts,jsx,tsx,mdx}'],
  theme: {
    extend: {
      container: {
        center: true,
        padding: {
          DEFAULT: '1rem',
          sm: '2rem',
          lg: '4rem',
          xl: '5rem'
        }
      },
      fontFamily: {
        sans: ['var(--font-inter)', 'sans-serif']
      },
      colors: {
        primary: {
          light: '#00FF7B',
          DEFAULT: '#00D768',
          dark: '#007137'
        },
        secondary: {
          light: '#00E0FF',
          DEFAULT: '#00B3CC',
          dark: '#007A8A'
        },
        dark: {
          light: '#171717',
          DEFAULT: '#0a0a0a',
          dark: '#050505'
        },
        teamcard: {
          border: '#00E0FF',
          bg: 'rgba(255, 255, 255, 0.03)'
        }
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
        'gradient-conic': 'conic-gradient(from 180deg at 50% 50%, var(--tw-gradient-stops))',
        'team-bg': 'linear-gradient(180deg, rgba(0,255,123,0.1) 0%, rgba(0,224,255,0.1) 100%)',
        'team-rays': 'radial-gradient(ellipse at center, rgba(0,255,123,0.2) 0%, transparent 70%)'
      },
      animation: {
        fadeIn: 'fadeIn 1s ease-in-out',
        slideUp: 'slideUp 0.8s ease-out',
        float: 'float 6s ease-in-out infinite',
        'pulse-slow': 'pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite'
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' }
        },
        slideUp: {
          '0%': { transform: 'translateY(20px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' }
        },
        float: {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-10px)' }
        }
      }
    }
  },
  plugins: []
};
