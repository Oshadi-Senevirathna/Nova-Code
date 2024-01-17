// material-ui
import { Snackbar, Alert, AlertTitle } from '../../../node_modules/@mui/material/index';

// ==============================|| SNACKBAR ||============================== //

const CustomSnackbar = ({ msg, onClose, severity, title }) => {
    return (
        <Snackbar
            anchorOrigin={{
                vertical: 'top',
                horizontal: 'right'
            }}
            open={!!msg}
            autoHideDuration={3000}
            onClose={onClose}
        >
            <Alert onClose={onClose} severity={severity} variant="filled">
                <AlertTitle>{title}</AlertTitle>
                {msg}
            </Alert>
        </Snackbar>
    );
};

export default CustomSnackbar;
