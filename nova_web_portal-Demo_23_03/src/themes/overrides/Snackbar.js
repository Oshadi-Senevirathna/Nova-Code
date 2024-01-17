// ==============================|| OVERRIDES - SNACKBAR ||============================== //

export default function Snackbar(theme) {
    return {
        MuiSnackbar: {
            styleOverrides: {
                anchorOriginTopRight: {
                    marginTop: '-20px',
                    marginRight: '-20px'
                }
            }
        }
    };
}
