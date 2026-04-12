import { createTheme } from '@mui/material/styles';

const theme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#36d399',
    },
    secondary: {
      main: '#60a5fa',
    },
    background: {
      default: '#08111f',
      paper: 'rgba(8, 17, 31, 0.82)',
    },
    text: {
      primary: '#f3f8ff',
      secondary: '#9fb2cc',
    },
  },
  typography: {
    fontFamily: '"IBM Plex Sans", system-ui, sans-serif',
    h1: {
      fontFamily: '"Space Grotesk", system-ui, sans-serif',
      fontWeight: 700,
    },
    h2: {
      fontFamily: '"Space Grotesk", system-ui, sans-serif',
      fontWeight: 700,
    },
    h3: {
      fontFamily: '"Space Grotesk", system-ui, sans-serif',
      fontWeight: 700,
    },
  },
  shape: {
    borderRadius: 20,
  },
  components: {
    MuiPaper: {
      styleOverrides: {
        root: {
          backdropFilter: 'blur(24px)',
          border: '1px solid rgba(145, 180, 255, 0.12)',
          backgroundImage: 'linear-gradient(180deg, rgba(12, 21, 38, 0.92), rgba(8, 17, 31, 0.88))',
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: 'none',
          borderRadius: 14,
          fontWeight: 700,
        },
      },
    },
  },
});

export default theme;
