import { createTheme } from '@mui/material/styles';

const theme = createTheme({
  palette: {
    mode: 'light',
    primary: {
      main: '#0f766e',
    },
    secondary: {
      main: '#d97706',
    },
    background: {
      default: '#f5f1e8',
      paper: 'rgba(255, 252, 247, 0.8)',
    },
    text: {
      primary: '#1f2b2d',
      secondary: '#58646a',
    },
  },
  typography: {
    fontFamily: '"Manrope", "Segoe UI", sans-serif',
    h1: {
      fontFamily: '"Fraunces", Georgia, serif',
      fontWeight: 600,
    },
    h2: {
      fontFamily: '"Fraunces", Georgia, serif',
      fontWeight: 600,
    },
    h3: {
      fontFamily: '"Fraunces", Georgia, serif',
      fontWeight: 600,
    },
  },
  shape: {
    borderRadius: 16,
  },
  components: {
    MuiPaper: {
      styleOverrides: {
        root: {
          backdropFilter: 'blur(10px)',
          border: '1px solid rgba(95, 88, 73, 0.18)',
          backgroundImage: 'linear-gradient(180deg, rgba(255, 252, 247, 0.93), rgba(250, 246, 238, 0.86))',
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
        containedPrimary: {
          backgroundImage: 'linear-gradient(135deg, #0f766e, #0ea5a0)',
          color: '#f8fffe',
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: {
          fontWeight: 700,
          borderRadius: 12,
        },
      },
    },
  },
});

export default theme;
