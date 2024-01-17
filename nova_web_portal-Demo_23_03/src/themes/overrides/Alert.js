// ==============================|| OVERRIDES - ALERT ||============================== //

export default function Alert(theme) {
    return {
        MuiAlert: {
            styleOverrides: {
                filledSuccess: {
                    width: '300px',
                    minHeight: '60px',
                    backgroundColor: theme.palette.success.light,
                    color: 'white'
                },
                filledError: {
                    width: '300px',
                    minHeight: '60px',
                    backgroundColor: theme.palette.error.light,
                    color: 'white'
                },
                filledWarning: {
                    width: '300px',
                    minHeight: '60px',
                    backgroundColor: theme.palette.warning.light,
                    color: 'white'
                },
                filledInfo: {
                    width: '300px',
                    minHeight: '60px',
                    backgroundColor: theme.palette.primary.light,
                    color: 'black'
                }
            }
        }
    };
}
